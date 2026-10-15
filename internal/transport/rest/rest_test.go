package rest

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jatimprovcsirt/panda-go/crypto"

	"github.com/jatimprovcsirt/panda-docker/internal/apierr"
	"github.com/jatimprovcsirt/panda-docker/internal/auth"
	"github.com/jatimprovcsirt/panda-docker/internal/service"
)

const testKID = "testkey"

func newTestServer(t *testing.T, maxBytes int64) *Server {
	t.Helper()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	t.Setenv("PANDA_KEY_testkey", base64.StdEncoding.EncodeToString(key))
	t.Setenv("PANDA_DEFAULT_KID", testKID)

	svc, err := service.New(service.Options{
		Cipher:   crypto.NewFieldCipher(crypto.NewLocalKeyProvider(), nil),
		IndexKey: []byte("an-index-key-for-tests-only-32b!!"),
	})
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}

	a, err := auth.NewAuthenticator(nil, auth.ModeNone)
	if err != nil {
		t.Fatalf("auth.NewAuthenticator: %v", err)
	}

	srv, err := New(Options{
		Service:         svc,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxRequestBytes: maxBytes,
		Authenticator:   a,
	})
	if err != nil {
		t.Fatalf("rest.New: %v", err)
	}
	return srv
}

func post(t *testing.T, srv *Server, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.9:1234"

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	var decoded map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
	return rec, decoded
}

// --- the round trip -------------------------------------------------------

func TestEncryptThenDecrypt(t *testing.T) {
	srv := newTestServer(t, 1<<20)

	const nik = "3201012501990001"

	enc, body := post(t, srv, "/v1/encrypt", `{"plaintext":"`+nik+`","kid":"`+testKID+`"}`)
	if enc.Code != http.StatusOK {
		t.Fatalf("encrypt status = %d, body = %s", enc.Code, enc.Body)
	}
	if body["v"] != float64(1) {
		t.Errorf("envelope version = %v, want 1", body["v"])
	}
	envelope, _ := body["envelope"].(string)
	if envelope == "" {
		t.Fatal("no envelope returned")
	}
	if strings.Contains(enc.Body.String(), nik) {
		t.Fatal("the response contains the plaintext")
	}

	dec, decBody := post(t, srv, "/v1/decrypt", `{"envelope":`+jsonString(envelope)+`}`)
	if dec.Code != http.StatusOK {
		t.Fatalf("decrypt status = %d, body = %s", dec.Code, dec.Body)
	}
	if decBody["value"] != "32************01" {
		t.Errorf("masked value = %v, want 32************01", decBody["value"])
	}
	if decBody["masked"] != true {
		t.Errorf("masked flag = %v, want true", decBody["masked"])
	}

	raw, rawBody := post(t, srv, "/v1/decrypt/raw", `{"envelope":`+jsonString(envelope)+`}`)
	if raw.Code != http.StatusOK {
		t.Fatalf("decrypt/raw status = %d, body = %s", raw.Code, raw.Body)
	}
	if rawBody["value"] != nik {
		t.Errorf("raw value = %v, want the plaintext", rawBody["value"])
	}
	if rawBody["masked"] != false {
		t.Errorf("masked flag = %v, want false", rawBody["masked"])
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// --- error shape ----------------------------------------------------------
//
// Every error, including the framework's own 404 and the body-limit failure,
// must come back in the same JSON shape. A client that has to special-case one
// error cannot parse errors uniformly.

func TestErrorsUseOneShape(t *testing.T) {
	srv := newTestServer(t, 1<<20)

	cases := []struct {
		name     string
		path     string
		body     string
		wantCode apierr.Code
		wantHTTP int
	}{
		{"malformed", "/v1/decrypt", `{"envelope":"not json"}`, apierr.CodeMalformedEnvelope, 400},
		{"empty plaintext", "/v1/encrypt", `{"plaintext":""}`, apierr.CodeInvalidPlaintext, 400},
		{"unknown endpoint", "/v1/nope", `{}`, apierr.CodeNotFound, 404},
		{"bad json", "/v1/encrypt", `{`, apierr.CodeMalformedEnvelope, 400},
		{"unknown field", "/v1/encrypt", `{"plaintex":"x"}`, apierr.CodeMalformedEnvelope, 400},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, body := post(t, srv, c.path, c.body)

			if rec.Code != c.wantHTTP {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, c.wantHTTP, rec.Body)
			}
			errObj, ok := body["error"].(map[string]any)
			if !ok {
				t.Fatalf("no error object in %s", rec.Body)
			}
			if errObj["code"] != string(c.wantCode) {
				t.Errorf("code = %v, want %v", errObj["code"], c.wantCode)
			}
			if msg, _ := errObj["message"].(string); msg == "" {
				t.Error("error has no message")
			}
			if _, leaked := body["message"]; leaked {
				t.Error("error fields are not nested under 'error'")
			}
		})
	}
}

func TestTamperedEnvelopeReturnsAuthFailed(t *testing.T) {
	srv := newTestServer(t, 1<<20)

	_, body := post(t, srv, "/v1/encrypt", `{"plaintext":"3201012501990001","kid":"`+testKID+`"}`)
	envelope, _ := body["envelope"].(string)

	env, err := crypto.ParseEnvelope(envelope)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
	raw[0] ^= 0xFF
	env.Ciphertext = base64.StdEncoding.EncodeToString(raw)
	tampered, _ := env.ToJSON()

	rec, tamperedBody := post(t, srv, "/v1/decrypt", `{"envelope":`+jsonString(tampered)+`}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	errObj := tamperedBody["error"].(map[string]any)
	if errObj["code"] != string(apierr.CodeAuthFailed) {
		t.Errorf("code = %v, want %v", errObj["code"], apierr.CodeAuthFailed)
	}
}

func TestInternalErrorsDoNotLeak(t *testing.T) {
	srv := newTestServer(t, 1<<20)

	// An envelope with a kid that has no key. The response must not say where
	// the service looked or what it found.
	_, body := post(t, srv, "/v1/encrypt", `{"plaintext":"3201012501990001","kid":"`+testKID+`"}`)
	envelope, _ := body["envelope"].(string)

	env, _ := crypto.ParseEnvelope(envelope)
	env.Kid = "../../etc/passwd"
	orphaned, _ := env.ToJSON()

	rec, orphanBody := post(t, srv, "/v1/decrypt", `{"envelope":`+jsonString(orphaned)+`}`)
	if strings.Contains(rec.Body.String(), "/etc/passwd") {
		t.Fatalf("the response echoed the kid back: %s", rec.Body)
	}
	if msg, _ := orphanBody["error"].(map[string]any)["message"].(string); strings.Contains(msg, "passwd") {
		t.Fatalf("the message leaks: %q", msg)
	}
}

// --- body limit -----------------------------------------------------------

func TestBodyLimitIsEnforced(t *testing.T) {
	srv := newTestServer(t, 64)

	huge := `{"plaintext":"` + strings.Repeat("A", 200) + `"}`
	rec, body := post(t, srv, "/v1/encrypt", huge)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body %s)", rec.Code, rec.Body)
	}
	if body["error"].(map[string]any)["code"] != string(apierr.CodePayloadTooLarge) {
		t.Errorf("code = %v, want %v", body["error"], apierr.CodePayloadTooLarge)
	}
}

// --- panic recovery -------------------------------------------------------

func TestPanicBecomesA500(t *testing.T) {
	// A handler that panics must not drop the connection. This is asserted
	// through the middleware directly, because no handler panics on purpose.
	svc := newTestServer(t, 1<<20)

	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("deliberate panic in a test")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	svc.recoverPanics(panicking).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "deliberate panic") {
		t.Error("the panic message reached the response")
	}
}

// --- health ---------------------------------------------------------------

func TestHealthEndpoints(t *testing.T) {
	handler := HealthHandler(func() bool { return true }, nil)

	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200", path, rec.Code)
		}
	}
}

func TestReadyzReportsNotReady(t *testing.T) {
	handler := HealthHandler(func() bool { return false }, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz = %d, want 503", rec.Code)
	}
}

func TestHealthzIgnoresReadiness(t *testing.T) {
	// Liveness must not fail because a dependency is down, or a key provider
	// outage would restart every pod at once.
	handler := HealthHandler(func() bool { return false }, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d, want 200 even when not ready", rec.Code)
	}
}

// --- other endpoints ------------------------------------------------------

func TestMaskEndpoint(t *testing.T) {
	srv := newTestServer(t, 1<<20)

	rec, body := post(t, srv, "/v1/mask", `{"value":"3201012501990001"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if body["value"] != "32************01" {
		t.Errorf("masked = %v", body["value"])
	}
}

func TestBlindIndexIsDeterministic(t *testing.T) {
	srv := newTestServer(t, 1<<20)

	_, a := post(t, srv, "/v1/blind-index", `{"value":"3201012501990001","kid":"`+testKID+`"}`)
	_, b := post(t, srv, "/v1/blind-index", `{"value":"3201012501990001","kid":"`+testKID+`"}`)

	if a["index"] == "" || a["index"] != b["index"] {
		t.Errorf("indexes differ: %v vs %v", a["index"], b["index"])
	}
}

func TestVersionEndpoint(t *testing.T) {
	srv := newTestServer(t, 1<<20)

	req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["service"] == "" {
		t.Error("no service description")
	}
}

func TestNewRequiresAService(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("a server was constructed with no service")
	}
}
