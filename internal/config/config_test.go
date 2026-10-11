package config

import (
	"errors"
	"strings"
	"testing"
)

// clearEnv removes every variable Load reads, so a test cannot pass because of
// something the developer happened to have exported. A config test that
// inherits the environment tests the environment.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"PANDA_API_PROTOCOL", "PANDA_ENV", "PANDA_LISTEN_ADDR",
		"PANDA_REST_PORT", "PANDA_GRPC_PORT", "PANDA_HEALTH_PORT",
		"PANDA_GRPC_REFLECTION", "PANDA_MAX_REQUEST_BYTES", "PANDA_MAX_BATCH_SIZE",
		"PANDA_RATE_LIMIT_RPS", "PANDA_RATE_LIMIT_BURST",
		"PANDA_REQUEST_TIMEOUT", "PANDA_SHUTDOWN_GRACE",
		"PANDA_ENABLE_SHRED", "PANDA_STARTUP_REQUIRE_KEY_PROVIDER",
		"PANDA_AUTH_MODE", "PANDA_TLS_ENABLED", "PANDA_TLS_CERT_FILE",
		"PANDA_TLS_KEY_FILE", "PANDA_TLS_CLIENT_CA_FILE",
		"PANDA_I_UNDERSTAND_THIS_IS_INSECURE", "PANDA_API_KEY_SOURCE",
		"PANDA_KEY_PROVIDER_DRIVER", "PANDA_LOG_FORMAT", "PANDA_LOG_LEVEL",
		"PANDA_AUDIT_SINK", "PANDA_AUDIT_FILE", "PANDA_AUDIT_WEBHOOK_URL",
		"PANDA_METRICS_ENABLED",
	} {
		t.Setenv(key, "")
	}
}

// validDevConfig sets the minimum for a configuration that should load.
func validDevConfig(t *testing.T) {
	t.Helper()
	t.Setenv("PANDA_API_PROTOCOL", "rest")
	t.Setenv("PANDA_ENV", "dev")
	t.Setenv("PANDA_AUTH_MODE", "apikey")
}

func TestProtocolIsRequired(t *testing.T) {
	clearEnv(t)
	t.Setenv("PANDA_ENV", "dev")

	_, err := Load()
	if err == nil {
		t.Fatal("expected an error when PANDA_API_PROTOCOL is unset")
	}

	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("expected *ConfigError, got %T", err)
	}
	if cfgErr.Variable != "PANDA_API_PROTOCOL" {
		t.Errorf("error names %q, want PANDA_API_PROTOCOL", cfgErr.Variable)
	}
}

func TestProtocolRejectsUnknownValues(t *testing.T) {
	clearEnv(t)
	t.Setenv("PANDA_ENV", "dev")
	t.Setenv("PANDA_API_PROTOCOL", "websocket")

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "websocket") {
		t.Fatalf("expected an error naming the bad value, got %v", err)
	}
}

func TestHealthPortMustNotCollide(t *testing.T) {
	clearEnv(t)
	validDevConfig(t)
	t.Setenv("PANDA_HEALTH_PORT", "8080") // same as the REST default

	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("expected a collision error, got %v", err)
	}
}

func TestDefaults(t *testing.T) {
	clearEnv(t)
	validDevConfig(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"RESTPort", cfg.RESTPort, 8080},
		{"GRPCPort", cfg.GRPCPort, 9090},
		{"HealthPort", cfg.HealthPort, 8081},
		{"MaxBatchSize", cfg.MaxBatchSize, 500},
		{"RateLimitRPS", cfg.RateLimitRPS, 100},
		{"EnableShred", cfg.EnableShred, false},
		{"GRPCReflection", cfg.GRPCReflection, false},
		{"TLSEnabled", cfg.TLSEnabled, true},
		{"MetricsEnabled", cfg.MetricsEnabled, true},
		{"KeyProviderDriver", cfg.KeyProviderDriver, "local"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

// --- the production gates -------------------------------------------------
//
// These are the refusals that keep the service from being deployed in a state
// it should not be reachable in. Each one is asserted, because a gate that
// quietly stopped working would never be noticed until it mattered.

func TestProductionRefusesWeakerAuthModes(t *testing.T) {
	for _, mode := range []string{"apikey", "none"} {
		t.Run(mode, func(t *testing.T) {
			clearEnv(t)
			t.Setenv("PANDA_API_PROTOCOL", "rest")
			t.Setenv("PANDA_ENV", "production")
			t.Setenv("PANDA_AUTH_MODE", mode)
			t.Setenv("PANDA_I_UNDERSTAND_THIS_IS_INSECURE", "true")

			_, err := Load()
			if err == nil {
				t.Fatalf("production accepted auth mode %q", mode)
			}
			if !strings.Contains(err.Error(), "PANDA_AUTH_MODE") {
				t.Errorf("error does not name the variable: %v", err)
			}
		})
	}
}

func TestAuthNoneRequiresAcknowledgement(t *testing.T) {
	clearEnv(t)
	t.Setenv("PANDA_API_PROTOCOL", "rest")
	t.Setenv("PANDA_ENV", "dev")
	t.Setenv("PANDA_AUTH_MODE", "none")
	// Deliberately not setting PANDA_I_UNDERSTAND_THIS_IS_INSECURE.

	_, err := Load()
	if err == nil {
		t.Fatal("auth mode 'none' was accepted without acknowledgement")
	}
	if !strings.Contains(err.Error(), "PANDA_I_UNDERSTAND_THIS_IS_INSECURE") {
		t.Errorf("error does not name the acknowledgement variable: %v", err)
	}
}

func TestMTLSRequiresCertificates(t *testing.T) {
	clearEnv(t)
	t.Setenv("PANDA_API_PROTOCOL", "rest")
	t.Setenv("PANDA_ENV", "production")
	t.Setenv("PANDA_AUTH_MODE", "mtls+apikey")
	// No certificate paths set.

	_, err := Load()
	if err == nil {
		t.Fatal("mTLS was accepted with no certificates configured")
	}
}

func TestMTLSRequiresClientCA(t *testing.T) {
	clearEnv(t)
	t.Setenv("PANDA_API_PROTOCOL", "rest")
	t.Setenv("PANDA_ENV", "production")
	t.Setenv("PANDA_AUTH_MODE", "mtls+apikey")
	t.Setenv("PANDA_TLS_CERT_FILE", "/etc/panda/tls/tls.crt")
	t.Setenv("PANDA_TLS_KEY_FILE", "/etc/panda/tls/tls.key")
	// Client CA deliberately absent: without it the server accepts any
	// certificate, which is not mutual authentication.

	_, err := Load()
	if err == nil {
		t.Fatal("mTLS was accepted with no client CA")
	}
	if !strings.Contains(err.Error(), "PANDA_TLS_CLIENT_CA_FILE") {
		t.Errorf("error does not name the client CA variable: %v", err)
	}
}

func TestShredIsOffByDefault(t *testing.T) {
	clearEnv(t)
	validDevConfig(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EnableShred {
		t.Error("crypto-shredding is enabled by default; it must be opt-in")
	}
}

// --- typed errors ---------------------------------------------------------

func TestBadValuesNameTheirVariable(t *testing.T) {
	cases := []struct{ key, value string }{
		{"PANDA_REST_PORT", "not-a-number"},
		{"PANDA_MAX_REQUEST_BYTES", "-5"},
		{"PANDA_RATE_LIMIT_RPS", "many"},
		{"PANDA_REQUEST_TIMEOUT", "soon"},
		{"PANDA_METRICS_ENABLED", "yes-please"},
		{"PANDA_KEY_PROVIDER_DRIVER", "carrier-pigeon"},
	}

	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			clearEnv(t)
			validDevConfig(t)
			t.Setenv(c.key, c.value)

			_, err := Load()
			if err == nil {
				t.Fatalf("%s=%q was accepted", c.key, c.value)
			}
			if !strings.Contains(err.Error(), c.key) {
				t.Errorf("error does not name %s: %v", c.key, err)
			}
		})
	}
}

func TestSummaryLineReportsWhatIsExposed(t *testing.T) {
	clearEnv(t)
	validDevConfig(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	line := cfg.SummaryLine()
	for _, want := range []string{"protocol=rest", "api=rest:8080", "auth=apikey", "key_provider=local"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary line missing %q: %s", want, line)
		}
	}

	// The grpc variant must not claim the REST port is open.
	t.Setenv("PANDA_API_PROTOCOL", "grpc")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(cfg.SummaryLine(), "api=grpc:9090") {
		t.Errorf("grpc summary line wrong: %s", cfg.SummaryLine())
	}
	if strings.Contains(cfg.SummaryLine(), "8080") {
		t.Errorf("grpc summary line mentions the REST port: %s", cfg.SummaryLine())
	}
}
