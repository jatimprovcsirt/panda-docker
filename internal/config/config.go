// Package config loads and validates the service configuration.
//
// Two rules shape everything here:
//
//  1. Fail fast, fail loudly. An invalid configuration exits with a structured
//     error rather than starting in a half-working state. A crypto service that
//     came up with the wrong TLS mode is worse than one that did not come up.
//
//  2. No defaults for anything that decides what is exposed. PANDA_API_PROTOCOL
//     has no default on purpose: a service that silently picks a protocol is a
//     service whose operator does not know what port is open.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Protocol is the transport this instance serves. Exactly one is active.
type Protocol string

const (
	ProtocolREST Protocol = "rest"
	ProtocolGRPC Protocol = "grpc"
)

// Env is the deployment environment. It gates which auth modes are permitted.
type Env string

const (
	EnvProduction Env = "production"
	EnvDev        Env = "dev"
	EnvLab        Env = "lab"
)

// AuthMode is how callers are authenticated.
type AuthMode string

const (
	// AuthMTLSAndAPIKey is the only mode permitted in production.
	AuthMTLSAndAPIKey AuthMode = "mtls+apikey"
	AuthMTLS          AuthMode = "mtls"
	AuthAPIKey        AuthMode = "apikey"
	AuthNone          AuthMode = "none"
)

// AuditSink is where audit records are written.
type AuditSink string

const (
	AuditStdout  AuditSink = "stdout"
	AuditFile    AuditSink = "file"
	AuditWebhook AuditSink = "webhook"
)

// Config is the fully validated service configuration.
type Config struct {
	Protocol Protocol
	Env      Env

	ListenAddr string
	RESTPort   int
	GRPCPort   int
	HealthPort int

	GRPCReflection bool

	MaxRequestBytes int64
	MaxBatchSize    int
	RateLimitRPS    int
	RateLimitBurst  int
	RequestTimeout  time.Duration
	ShutdownGrace   time.Duration

	EnableShred               bool
	StartupRequireKeyProvider bool

	AuthMode          AuthMode
	TLSEnabled        bool
	TLSCertFile       string
	TLSKeyFile        string
	TLSClientCAFile   string
	AllowInsecure     bool
	APIKeySource      string
	KeyProviderDriver string

	LogFormat      string
	LogLevel       string
	AuditSink      AuditSink
	AuditFile      string
	AuditWebhook   string
	MetricsEnabled bool
}

// ConfigError names the variable at fault, so an operator does not have to
// guess which of thirty settings was rejected.
type ConfigError struct {
	Variable string
	Problem  string
	Hint     string
}

func (e *ConfigError) Error() string {
	msg := fmt.Sprintf("%s: %s", e.Variable, e.Problem)
	if e.Hint != "" {
		msg += " (" + e.Hint + ")"
	}
	return msg
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:   envOr("PANDA_LISTEN_ADDR", "0.0.0.0"),
		LogFormat:    envOr("PANDA_LOG_FORMAT", "json"),
		LogLevel:     envOr("PANDA_LOG_LEVEL", "info"),
		AuditSink:    AuditSink(envOr("PANDA_AUDIT_SINK", string(AuditStdout))),
		AuditFile:    os.Getenv("PANDA_AUDIT_FILE"),
		AuditWebhook: os.Getenv("PANDA_AUDIT_WEBHOOK_URL"),
		Env:          Env(envOr("PANDA_ENV", string(EnvProduction))),
		APIKeySource: os.Getenv("PANDA_API_KEY_SOURCE"),
	}

	var err error

	// --- required, no default ---------------------------------------------
	//
	// The absence of a default is the point. A service that picks a protocol
	// when none is configured opens a port nobody chose.
	rawProtocol := os.Getenv("PANDA_API_PROTOCOL")
	if rawProtocol == "" {
		return nil, &ConfigError{
			Variable: "PANDA_API_PROTOCOL",
			Problem:  "is required and has no default",
			Hint:     "set it to 'rest' or 'grpc' to choose which interface this instance serves",
		}
	}
	cfg.Protocol = Protocol(rawProtocol)
	if cfg.Protocol != ProtocolREST && cfg.Protocol != ProtocolGRPC {
		return nil, &ConfigError{
			Variable: "PANDA_API_PROTOCOL",
			Problem:  fmt.Sprintf("is %q", rawProtocol),
			Hint:     "accepted values are 'rest' and 'grpc'",
		}
	}

	if cfg.Env != EnvProduction && cfg.Env != EnvDev && cfg.Env != EnvLab {
		return nil, &ConfigError{
			Variable: "PANDA_ENV",
			Problem:  fmt.Sprintf("is %q", cfg.Env),
			Hint:     "accepted values are 'production', 'dev', and 'lab'",
		}
	}

	// --- ports -------------------------------------------------------------
	if cfg.RESTPort, err = envInt("PANDA_REST_PORT", 8080); err != nil {
		return nil, err
	}
	if cfg.GRPCPort, err = envInt("PANDA_GRPC_PORT", 9090); err != nil {
		return nil, err
	}
	if cfg.HealthPort, err = envInt("PANDA_HEALTH_PORT", 8081); err != nil {
		return nil, err
	}

	// The health listener is always on. Colliding with it would mean either the
	// API or the probes are unreachable, and both failures are silent.
	if cfg.HealthPort == cfg.RESTPort || cfg.HealthPort == cfg.GRPCPort {
		return nil, &ConfigError{
			Variable: "PANDA_HEALTH_PORT",
			Problem:  "collides with an API port",
			Hint:     fmt.Sprintf("health=%d rest=%d grpc=%d", cfg.HealthPort, cfg.RESTPort, cfg.GRPCPort),
		}
	}

	// --- limits ------------------------------------------------------------
	if cfg.MaxRequestBytes, err = envInt64("PANDA_MAX_REQUEST_BYTES", 1<<20); err != nil {
		return nil, err
	}
	if cfg.MaxBatchSize, err = envInt("PANDA_MAX_BATCH_SIZE", 500); err != nil {
		return nil, err
	}
	if cfg.RateLimitRPS, err = envInt("PANDA_RATE_LIMIT_RPS", 100); err != nil {
		return nil, err
	}
	if cfg.RateLimitBurst, err = envInt("PANDA_RATE_LIMIT_BURST", 200); err != nil {
		return nil, err
	}
	if cfg.RequestTimeout, err = envDuration("PANDA_REQUEST_TIMEOUT", 10*time.Second); err != nil {
		return nil, err
	}
	if cfg.ShutdownGrace, err = envDuration("PANDA_SHUTDOWN_GRACE", 15*time.Second); err != nil {
		return nil, err
	}

	// --- flags -------------------------------------------------------------
	if cfg.GRPCReflection, err = envBool("PANDA_GRPC_REFLECTION", false); err != nil {
		return nil, err
	}
	if cfg.EnableShred, err = envBool("PANDA_ENABLE_SHRED", false); err != nil {
		return nil, err
	}
	if cfg.MetricsEnabled, err = envBool("PANDA_METRICS_ENABLED", true); err != nil {
		return nil, err
	}
	if cfg.StartupRequireKeyProvider, err = envBool("PANDA_STARTUP_REQUIRE_KEY_PROVIDER", true); err != nil {
		return nil, err
	}

	// --- auth and TLS ------------------------------------------------------
	if err := loadSecurity(cfg); err != nil {
		return nil, err
	}

	// --- key provider ------------------------------------------------------
	cfg.KeyProviderDriver = envOr("PANDA_KEY_PROVIDER_DRIVER", "local")
	switch cfg.KeyProviderDriver {
	case "local", "vault", "infisical":
	default:
		return nil, &ConfigError{
			Variable: "PANDA_KEY_PROVIDER_DRIVER",
			Problem:  fmt.Sprintf("is %q", cfg.KeyProviderDriver),
			Hint:     "accepted values are 'local', 'vault', and 'infisical'",
		}
	}

	return cfg, nil
}

// loadSecurity validates the auth and TLS settings.
//
// This is where the service decides whether it can be safely exposed, so the
// production checks are refusals rather than warnings. A warning in a startup
// log is a warning nobody reads.
func loadSecurity(cfg *Config) error {
	var err error

	cfg.AuthMode = AuthMode(envOr("PANDA_AUTH_MODE", string(AuthMTLSAndAPIKey)))

	if cfg.TLSEnabled, err = envBool("PANDA_TLS_ENABLED", true); err != nil {
		return err
	}
	if cfg.AllowInsecure, err = envBool("PANDA_I_UNDERSTAND_THIS_IS_INSECURE", false); err != nil {
		return err
	}

	cfg.TLSCertFile = os.Getenv("PANDA_TLS_CERT_FILE")
	cfg.TLSKeyFile = os.Getenv("PANDA_TLS_KEY_FILE")
	cfg.TLSClientCAFile = os.Getenv("PANDA_TLS_CLIENT_CA_FILE")

	switch cfg.AuthMode {
	case AuthMTLSAndAPIKey, AuthMTLS:
	case AuthAPIKey:
		// Permitted for an isolated lab cluster, which is where OPDs evaluate
		// the service before they have a PKI. Never in production.
		if cfg.Env == EnvProduction {
			return &ConfigError{
				Variable: "PANDA_AUTH_MODE",
				Problem:  "is 'apikey', which is not permitted when PANDA_ENV=production",
				Hint:     "use 'mtls+apikey'; a bearer secret alone is replayable from anywhere on the network",
			}
		}
	case AuthNone:
		if cfg.Env == EnvProduction {
			return &ConfigError{
				Variable: "PANDA_AUTH_MODE",
				Problem:  "is 'none', which is not permitted when PANDA_ENV=production",
				Hint:     "an unauthenticated decryption endpoint is not a configuration, it is an incident",
			}
		}
		if !cfg.AllowInsecure {
			return &ConfigError{
				Variable: "PANDA_I_UNDERSTAND_THIS_IS_INSECURE",
				Problem:  "must be 'true' to run with PANDA_AUTH_MODE=none",
				Hint:     "this deliberately makes the service reachable by anything that can route to it",
			}
		}
	default:
		return &ConfigError{
			Variable: "PANDA_AUTH_MODE",
			Problem:  fmt.Sprintf("is %q", cfg.AuthMode),
			Hint:     "accepted values are 'mtls+apikey', 'mtls', 'apikey', and 'none'",
		}
	}

	needsMTLS := cfg.AuthMode == AuthMTLSAndAPIKey || cfg.AuthMode == AuthMTLS

	if needsMTLS {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return &ConfigError{
				Variable: "PANDA_TLS_CERT_FILE / PANDA_TLS_KEY_FILE",
				Problem:  "are required when mTLS is enabled",
				Hint:     "point them at the server certificate and key",
			}
		}
		if cfg.AuthMode == AuthMTLSAndAPIKey && cfg.TLSClientCAFile == "" {
			return &ConfigError{
				Variable: "PANDA_TLS_CLIENT_CA_FILE",
				Problem:  "is required to verify client certificates",
				Hint:     "without it the server would accept any certificate, which is not mTLS",
			}
		}
	}

	return nil
}

// SummaryLine is the structured startup record (PRD FR-D9). It answers "what
// mode is this pod in?" from `kubectl logs` without reading the config back.
func (c *Config) SummaryLine() string {
	api := fmt.Sprintf("rest:%d", c.RESTPort)
	if c.Protocol == ProtocolGRPC {
		api = fmt.Sprintf("grpc:%d", c.GRPCPort)
	}

	parts := []string{
		"protocol=" + string(c.Protocol),
		"api=" + api,
		"health=:" + strconv.Itoa(c.HealthPort),
		"env=" + string(c.Env),
		"auth=" + string(c.AuthMode),
		"key_provider=" + c.KeyProviderDriver,
		"tls=" + strconv.FormatBool(c.TLSEnabled),
		"shred=" + strconv.FormatBool(c.EnableShred),
	}
	return strings.Join(parts, " ")
}

// --- helpers ---------------------------------------------------------------

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, &ConfigError{Variable: key, Problem: fmt.Sprintf("is not an integer: %q", raw)}
	}
	if v < 0 {
		return 0, &ConfigError{Variable: key, Problem: fmt.Sprintf("is negative: %d", v)}
	}
	return v, nil
}

func envInt64(key string, fallback int64) (int64, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, &ConfigError{Variable: key, Problem: fmt.Sprintf("is not an integer: %q", raw)}
	}
	if v <= 0 {
		return 0, &ConfigError{Variable: key, Problem: fmt.Sprintf("must be positive, got %d", v)}
	}
	return v, nil
}

func envBool(key string, fallback bool) (bool, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, &ConfigError{
			Variable: key,
			Problem:  fmt.Sprintf("is not a boolean: %q", raw),
			Hint:     "accepted values are 'true', 'false', '1', and '0'",
		}
	}
	return v, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return 0, &ConfigError{
			Variable: key,
			Problem:  fmt.Sprintf("is not a duration: %q", raw),
			Hint:     "use Go duration syntax, for example '10s' or '1m30s'",
		}
	}
	if v <= 0 {
		return 0, &ConfigError{Variable: key, Problem: fmt.Sprintf("must be positive, got %s", v)}
	}
	return v, nil
}
