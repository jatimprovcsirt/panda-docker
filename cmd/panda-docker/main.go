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
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jatimprovcsirt/panda-go/crypto"

	"github.com/jatimprovcsirt/panda-docker/internal/config"
	"github.com/jatimprovcsirt/panda-docker/internal/logging"
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

	healthSrv := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.HealthPort),
		Handler:           rest.HealthHandler(func() bool { return ready }),
		ReadHeaderTimeout: 5 * time.Second,
	}

	apiHandler, apiAddr, err := buildAPI(cfg, svc, log)
	if err != nil {
		log.Error("could not build the API handler", "error", err)
		return exitRefused
	}

	// TLS is not wired yet — it belongs to Phase 3, and the certificates the
	// config validates are not yet loaded. Say so loudly rather than letting
	// the config imply a protection that is not there.
	//
	// This warning exists because the failure is silent otherwise: an operator
	// who sets PANDA_TLS_ENABLED=true and sees no complaint would reasonably
	// conclude the listener is encrypted. It is not.
	if cfg.TLSEnabled {
		log.Warn("TLS is configured but not yet implemented; the API listener is plain HTTP. " +
			"Do not expose this instance outside an isolated network until the hardening phase lands.")
	}

	apiSrv := &http.Server{
		Addr:              apiAddr,
		Handler:           apiHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.RequestTimeout,
		WriteTimeout:      cfg.RequestTimeout,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 2)

	go func() {
		log.Info("health listener bound", "addr", healthSrv.Addr)
		if err := healthSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("health listener: %w", err)
		}
	}()

	go func() {
		log.Info("api listener bound", "addr", apiSrv.Addr, "protocol", string(cfg.Protocol))
		if err := apiSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	if err := apiSrv.Shutdown(ctx); err != nil {
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
