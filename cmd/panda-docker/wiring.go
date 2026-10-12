package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/jatimprovcsirt/panda-go/crypto"

	pandav1 "github.com/jatimprovcsirt/panda-docker/gen/panda/v1"
	"github.com/jatimprovcsirt/panda-docker/internal/config"
	"github.com/jatimprovcsirt/panda-docker/internal/service"
	"github.com/jatimprovcsirt/panda-docker/internal/transport/grpctransport"
	"github.com/jatimprovcsirt/panda-docker/internal/transport/rest"
)

// apiServer is what serve() drives, whichever protocol is active.
//
// Introduced because grpc.Server and http.Server agree on Serve but not on
// shutdown — grpc has GracefulStop, http has Shutdown(ctx). A small interface
// with an adapter is cheaper than branching inside the lifecycle code, where
// the two paths would drift.
type apiServer interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
}

// grpcLifecycle adapts *grpc.Server to apiServer.
type grpcLifecycle struct{ srv *grpc.Server }

func (g grpcLifecycle) Serve(ln net.Listener) error { return g.srv.Serve(ln) }

func (g grpcLifecycle) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		// GracefulStop waits for in-flight RPCs, which is what a rolling
		// update needs: a decrypt in progress must finish rather than be cut
		// off mid-response.
		g.srv.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		// The grace period expired. Stop forcibly rather than hanging the
		// pod past its termination deadline.
		g.srv.Stop()
		return ctx.Err()
	}
}

type slogLogger = slog.Logger

// buildAPI constructs the handler for whichever protocol is active.
//
// The inactive protocol is not built at all. It would be easy to construct
// both and bind one, but then a future change that binds the wrong one is a
// silent exposure rather than a compile-time absence.
func buildAPI(cfg *config.Config, svc *service.Service, log *slog.Logger) (apiServer, string, error) {
	switch cfg.Protocol {
	case config.ProtocolREST:
		srv, err := rest.New(rest.Options{
			Service:         svc,
			Logger:          log,
			MaxRequestBytes: cfg.MaxRequestBytes,
		})
		if err != nil {
			return nil, "", err
		}
		return &http.Server{
			Handler:           srv.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       cfg.RequestTimeout,
			WriteTimeout:      cfg.RequestTimeout,
			IdleTimeout:       120 * time.Second,
		}, fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.RESTPort), nil

	case config.ProtocolGRPC:
		handler, err := grpctransport.New(svc, log)
		if err != nil {
			return nil, "", err
		}

		grpcSrv := grpc.NewServer(
			grpc.ChainUnaryInterceptor(grpctransport.RecoverInterceptor(log)),
		)
		pandav1.RegisterPandaServiceServer(grpcSrv, handler)

		// The standard health service, so Kubernetes can use a native gRPC
		// probe instead of an HTTP shim that only works for one protocol.
		healthSrv := health.NewServer()
		healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
		healthpb.RegisterHealthServer(grpcSrv, healthSrv)

		// Reflection lets grpcurl work without a local copy of the proto.
		// Off by default because it also lets anyone enumerate the API, which
		// is a convenience in development and a small disclosure in
		// production.
		if cfg.GRPCReflection {
			reflection.Register(grpcSrv)
		} else {
			log.Info("gRPC reflection is disabled; set PANDA_GRPC_REFLECTION=true for grpcurl")
		}

		return grpcLifecycle{srv: grpcSrv}, fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.GRPCPort), nil
	}

	return nil, "", fmt.Errorf("unhandled protocol %q", cfg.Protocol)
}

// buildKeyProvider constructs the provider the configuration names.
//
// The provider is the only place encryption keys enter this process, and it
// never stores them: every driver reads from somewhere outside the container,
// which is what lets the container be treated as disposable.
func buildKeyProvider(cfg *config.Config) (crypto.KeyProvider, error) {
	switch cfg.KeyProviderDriver {
	case "local":
		return crypto.NewLocalKeyProvider(), nil

	case "vault":
		url := os.Getenv("PANDA_VAULT_URL")
		if url == "" {
			return nil, errors.New("PANDA_VAULT_URL is required when the vault driver is selected")
		}
		mount := envOr("PANDA_VAULT_MOUNT_PATH", "secret")

		// AppRole is the production path; a static token is accepted because
		// the SDK documents it for development, and refusing it here would
		// make the two disagree about what is configurable.
		if token := os.Getenv("PANDA_VAULT_TOKEN"); token != "" {
			return crypto.NewVaultKeyProvider(url, token, mount), nil
		}

		roleID := os.Getenv("PANDA_VAULT_ROLE_ID")
		secretID := os.Getenv("PANDA_VAULT_SECRET_ID")
		if roleID == "" || secretID == "" {
			return nil, errors.New(
				"the vault driver needs either PANDA_VAULT_TOKEN, or PANDA_VAULT_ROLE_ID and PANDA_VAULT_SECRET_ID")
		}

		return crypto.NewVaultKeyProviderWithConfig(crypto.VaultKeyProviderConfig{
			VaultURL:  url,
			MountPath: mount,
			Namespace: os.Getenv("PANDA_VAULT_NAMESPACE"),
			RoleID:    roleID,
			SecretID:  secretID,
			AuthToken: "approle",
			TokenTTL:  envInt("PANDA_VAULT_TOKEN_TTL", 3600),
		}), nil

	case "infisical":
		siteURL := envOr("PANDA_INFISICAL_SITE_URL", "https://app.infisical.com")
		clientID := os.Getenv("PANDA_INFISICAL_CLIENT_ID")
		clientSecret := os.Getenv("PANDA_INFISICAL_CLIENT_SECRET")
		projectID := os.Getenv("PANDA_INFISICAL_PROJECT_ID")

		if clientID == "" || clientSecret == "" || projectID == "" {
			return nil, errors.New(
				"the infisical driver needs PANDA_INFISICAL_CLIENT_ID, PANDA_INFISICAL_CLIENT_SECRET, and PANDA_INFISICAL_PROJECT_ID")
		}

		return crypto.NewInfisicalKeyProvider(
			siteURL, clientID, clientSecret, projectID,
			envOr("PANDA_INFISICAL_ENVIRONMENT", "dev"),
			envInt("PANDA_INFISICAL_CACHE_TTL", 300),
		), nil
	}

	return nil, fmt.Errorf("unsupported key provider driver %q", cfg.KeyProviderDriver)
}

// indexKeyFromEnv reads the blind-index key.
//
// Separate from the encryption keys on purpose: a leaked index key does not
// expose any plaintext, and a leaked encryption key does not let an attacker
// forge a matching index. Reusing one key for both would collapse that.
func indexKeyFromEnv() []byte {
	raw := os.Getenv("PANDA_INDEX_KEY")
	if raw == "" {
		// No index key means blind indexing reports an error rather than
		// computing a weaker index the caller cannot distinguish.
		return nil
	}

	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// Accept a raw value too, so an operator who put a passphrase in
		// rather than base64 gets something that works rather than silence.
		return []byte(raw)
	}
	return decoded
}

// auditSinkFor builds the audit destination.
func auditSinkFor(cfg *config.Config, log *slog.Logger) service.AuditSink {
	switch cfg.AuditSink {
	case config.AuditStdout:
		return service.NewWriterSink(os.Stdout)

	case config.AuditFile:
		f, err := os.OpenFile(cfg.AuditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			log.Error("could not open the audit file; falling back to stdout",
				"path", cfg.AuditFile, "error", err)
			return service.NewWriterSink(os.Stdout)
		}
		return service.NewWriterSink(f)

	case config.AuditWebhook:
		// Deliberately not implemented as a network call. This service's claim
		// is that it makes no outbound requests; shipping a webhook sink would
		// make that false, and a per-request outbound call from a decryption
		// service is a data-egress path that needs its own review.
		log.Warn("PANDA_AUDIT_SINK=webhook is not available; audit records go to stdout")
		return service.NewWriterSink(os.Stdout)
	}

	return service.NewWriterSink(os.Stdout)
}

// healthcheck probes the local readiness endpoint.
//
// It exists as a subcommand because the runtime image is distroless: there is
// no shell, no curl, and no wget, so a HEALTHCHECK instruction has nothing to
// run but the binary itself.
func healthcheck(args []string) int {
	url := "http://127.0.0.1:8081/readyz"
	for i, a := range args {
		if strings.HasPrefix(a, "--url=") {
			url = strings.TrimPrefix(a, "--url=")
		} else if a == "--url" && i+1 < len(args) {
			url = args[i+1]
		}
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
		return exitFailure
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: %s returned %d\n", url, resp.StatusCode)
		return exitFailure
	}
	fmt.Println("ready")
	return exitOK
}

// --- small env helpers -----------------------------------------------------

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v, err := strconv.ParseBool(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return v
}

func envInt(key string, fallback int) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return v
}
