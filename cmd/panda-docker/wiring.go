package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jatimprovcsirt/panda-go/crypto"

	"github.com/jatimprovcsirt/panda-docker/internal/config"
	"github.com/jatimprovcsirt/panda-docker/internal/service"
	"github.com/jatimprovcsirt/panda-docker/internal/transport/rest"
)

type slogLogger = slog.Logger

// buildAPI constructs the handler for whichever protocol is active.
//
// The inactive protocol is not built at all. It would be easy to construct
// both and bind one, but then a future change that binds the wrong one is a
// silent exposure rather than a compile-time absence.
func buildAPI(cfg *config.Config, svc *service.Service, log *slog.Logger) (http.Handler, string, error) {
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
		return srv.Handler(), fmt.Sprintf("%s:%d", cfg.ListenAddr, cfg.RESTPort), nil

	case config.ProtocolGRPC:
		// Phase 2. Refusing here rather than falling back to REST is the point:
		// an operator who asked for gRPC and silently got REST would have
		// opened the wrong port and be none the wiser.
		return nil, "", errors.New(
			"PANDA_API_PROTOCOL=grpc is not implemented yet; the gRPC transport lands in Phase 2. " +
				"Set PANDA_API_PROTOCOL=rest or wait for the release that includes it",
		)
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
