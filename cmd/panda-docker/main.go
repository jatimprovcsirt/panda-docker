// Command panda-docker serves PANDA's field-level encryption over a network
// API.
//
// This binary is a transport wrapper around the PANDA SDK, not a second
// implementation of it. There is no cryptography in this repository: the
// encryption, masking, and blind indexing all come from panda-go, which is
// what keeps the wire format identical to the SDKs and lets the tests assert
// interoperability rather than hope for it.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jatimprovcsirt/panda-go/crypto"

	"github.com/jatimprovcsirt/panda-docker/internal/config"
	"github.com/jatimprovcsirt/panda-docker/internal/logging"
	"github.com/jatimprovcsirt/panda-docker/internal/metrics"
	"github.com/jatimprovcsirt/panda-docker/internal/ratelimit"
	"github.com/jatimprovcsirt/panda-docker/internal/service"
	"github.com/jatimprovcsirt/panda-docker/internal/transport/rest"
)

// Exit codes: 0 ok, 2 configuration refused, 1 runtime failure. Distinguishing
// refusal from failure matters because Kubernetes treats them the same but an
// operator does not: a refusal means fix the config, a failure means look at
// the logs.
const (
	exitOK      = 0
	exitFailure = 1
	exitRefused = 2
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			return healthcheck(os.Args[2:])
		case "version":
			fmt.Println(service.SDKVersion())
			return exitOK
		case "help", "--help", "-h":
			usage()
			return exitOK
		}
	}

	cfg, err := config.Load()
	if err != nil {
		// Logging is not up yet, so this goes to stderr directly. A refusal
		// has to be readable, and a JSON log line is not more readable than a
		// sentence.
		fmt.Fprintf(os.Stderr, "configuration refused: %v\n", err)
		return exitRefused
	}

	log := logging.New(cfg.LogFormat, cfg.LogLevel)

	provider, err := buildKeyProvider(cfg)
	if err != nil {
		log.Error("could not construct the key provider", "error", err)
		return exitRefused
	}

	svc, err := service.New(service.Options{
		Cipher:   crypto.NewFieldCipher(provider, nil, nil),
		Audit:    auditSinkFor(cfg, log),
		IndexKey: indexKeyFromEnv(),
	})
	if err != nil {
		log.Error("could not construct the service", "error", err)
		return exitRefused
	}

	// The startup summary answers "what mode is this pod in?" from
	// `kubectl logs`, without reading the config back or exec-ing into the pod.
	log.Info("panda-docker starting",
		"summary", cfg.SummaryLine(),
		"sdk", service.SDKVersion(),
	)

	return serve(cfg, svc, log)
}

// serve binds exactly one API listener plus the health listener.
//
// Exactly one: the inactive protocol's port is never opened, so a
// misconfiguration cannot silently expose an interface nobody chose.
func serve(cfg *config.Config, svc *service.Service, log *slogLogger) int {
	ready := true

	// Constructed here rather than in run() so the lifecycle owns everything
	// that serves: a registry built earlier and passed through would be one
	// more thing that could be wired to the wrong instance.
	reg := metrics.New(service.SDKVersion(), string(cfg.Protocol), cfg.KeyProviderDriver)

	limiter := ratelimit.New(cfg.RateLimitRPS, cfg.RateLimitBurst)
	if cfg.RateLimitRPS <= 0 {
		log.Warn("rate limiting is disabled (PANDA_RATE_LIMIT_RPS=0); " +
			"every credential shares the service's full capacity")
	}

	var metricsHandler http.Handler
	if cfg.MetricsEnabled {
		metricsHandler = reg.Handler()
	} else {
		log.Warn("metrics are disabled (PANDA_METRICS_ENABLED=false); " +
			"the unmask counter is the signal an anomalous bulk read would show up in")
	}

	healthSrv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.HealthPort),
		Handler:           rest.HealthHandler(func() bool { return ready }, metricsHandler),
		ReadHeaderTimeout: 5 * time.Second,
	}

	authenticator, err := buildAuthenticator(cfg)
	if err != nil {
		log.Error("could not build the authentication layer", "error", err)
		return exitRefused
	}
	log.Info("authentication configured", "mode", string(cfg.AuthMode))

	api, apiAddr, err := buildAPI(cfg, svc, authenticator, reg, limiter, log)
	if err != nil {
		log.Error("could not build the API", "error", err)
		return exitRefused
	}

	// The listener is wrapped in TLS by the server type itself, so a service
	// configured for TLS cannot come up without it: buildTLS refuses rather
	// than returning a nil config that would serve plaintext.
	if !cfg.TLSEnabled {
		log.Warn("TLS is disabled; the API listener is plain HTTP. " +
			"This is acceptable only on an isolated network, and is refused entirely in production " +
			"unless the auth mode acknowledges it.")
	}

	// net.Listen is called here rather than letting the server bind, so a
	// port that is already taken is reported as a startup failure rather than
	// as a listener error arriving after the process has claimed to start.
	ln, err := net.Listen("tcp", apiAddr)
	if err != nil {
		log.Error("could not bind the API listener", "addr", apiAddr, "error", err)
		return exitFailure
	}

	errCh := make(chan error, 2)

	go func() {
		log.Info("health listener bound", "addr", healthSrv.Addr)
		if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("health listener: %w", err)
		}
	}()

	go func() {
		log.Info("api listener bound", "addr", apiAddr, "protocol", string(cfg.Protocol))
		if err := api.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("api listener: %w", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Error("listener failed", "error", err)
		return exitFailure
	case sig := <-stop:
		log.Info("shutting down", "signal", sig.String())
	}

	// Stop reporting ready first, so anything watching readiness stops sending
	// new work before the drain begins.
	ready = false

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()

	if err := api.Shutdown(ctx); err != nil {
		log.Error("api listener did not drain in time", "error", err)
	}
	if err := healthSrv.Shutdown(ctx); err != nil {
		log.Error("health listener did not stop cleanly", "error", err)
	}

	log.Info("stopped")
	return exitOK
}

func usage() {
	fmt.Fprint(os.Stderr, `panda-docker — PANDA field-level encryption over an API

USAGE
  panda-docker              serve (protocol chosen by PANDA_API_PROTOCOL)
  panda-docker healthcheck  probe the local readiness endpoint
  panda-docker version      print the linked PANDA SDK version

Configuration is entirely environment-driven. See the repository README.
`)
}
