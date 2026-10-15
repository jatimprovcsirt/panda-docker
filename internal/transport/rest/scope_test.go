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

// These tests exercise the authorisation boundary at the transport, which is
// where it actually protects anything. The scope logic is unit-tested in
// internal/auth; what matters here is that the route wiring calls it.

type scopeFixture struct {
	handler http.Handler
	tokens  map[string]string // key id -> token
}

func newScopeFixture(t *testing.T) *scopeFixture {
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

	// Three credentials with deliberately different powers.
	grants := map[string][]auth.Scope{
		"writer":     {auth.ScopeEncrypt, auth.ScopeBlindIndex},
		"reader":     {auth.ScopeDecrypt},
		"backoffice": {auth.ScopeDecrypt, auth.ScopeUnmask},
	}

	tokens := make(map[string]string, len(grants))
	var records []auth.Record
	for id, scopes := range grants {
		token, err := auth.GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken: %v", err)
		}
		hash, err := auth.HashToken(token, auth.DefaultParams())
		if err != nil {
			t.Fatalf("HashToken: %v", err)
		}
		raw := make([]string, len(scopes))
		for i, s := range scopes {
			raw[i] = string(s)
		}
		records = append(records, auth.Record{ID: id, Hash: hash, Scopes: raw})
		tokens[id] = token
	}

	store, err := auth.NewFileStore(mustJSON(t, records))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	a, err := auth.NewAuthenticator(store, auth.ModeAPIKey)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	srv, err := New(Options{
		Service:         svc,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxRequestBytes: 1 << 20,
		Authenticator:   a,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return &scopeFixture{handler: srv.Handler(), tokens: tokens}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func (f *scopeFixture) call(t *testing.T, as, path, body string) (int, map[string]any) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token, ok := f.tokens[as]; ok {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	var decoded map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
	return rec.Code, decoded
}

func (f *scopeFixture) encryptAs(t *testing.T, as string) string {
	t.Helper()
	code, body := f.call(t, as, "/v1/encrypt", `{"plaintext":"3201012501990001","kid":"`+testKID+`"}`)
	if code != http.StatusOK {
		t.Fatalf("encrypt as %s returned %d: %v", as, code, body)
	}
	envelope, _ := body["envelope"].(string)
	return envelope
}

// --- no credentials -------------------------------------------------------

func TestRequestsWithoutACredentialAreRefused(t *testing.T) {
	f := newScopeFixture(t)

	for _, path := range []string{"/v1/encrypt", "/v1/decrypt", "/v1/decrypt/raw", "/v1/mask"} {
		code, body := f.call(t, "", path, `{}`)
		if code != http.StatusUnauthorized {
			t.Errorf("%s without a credential returned %d, want 401", path, code)
		}
		if body["error"].(map[string]any)["code"] != string(apierr.CodeUnauthorized) {
			t.Errorf("%s error code = %v", path, body["error"])
		}
	}
}

func TestAGarbageCredentialIsRefused(t *testing.T) {
	f := newScopeFixture(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/decrypt", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer panda_svc_notarealkeyatallnotarealkey")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestVersionNeedsNoCredential(t *testing.T) {
	// An operator debugging a deployment has to be able to ask what is
	// running before they can authenticate against it.
	f := newScopeFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("/v1/version returned %d without a credential, want 200", rec.Code)
	}
}

// --- the gate the whole design rests on -----------------------------------

func TestDecryptOnlyKeyCannotUnmask(t *testing.T) {
	f := newScopeFixture(t)
	envelope := f.encryptAs(t, "writer")

	body, _ := json.Marshal(map[string]string{"envelope": envelope})

	// The same key that can read the masked value...
	if code, _ := f.call(t, "reader", "/v1/decrypt", string(body)); code != http.StatusOK {
		t.Fatalf("a decrypt-scoped key could not read a masked value: %d", code)
	}

	// ...cannot read the full one.
	code, resp := f.call(t, "reader", "/v1/decrypt/raw", string(body))
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 — a decrypt-only key reached the unmask path", code)
	}

	errObj, _ := resp["error"].(map[string]any)
	if errObj["code"] != string(apierr.CodeForbidden) {
		t.Errorf("error code = %v, want %v", errObj["code"], apierr.CodeForbidden)
	}
	if resp["value"] != nil {
		t.Fatal("the response carried a value despite being refused")
	}
}

func TestUnmaskScopeIsGrantedSeparately(t *testing.T) {
	f := newScopeFixture(t)
	envelope := f.encryptAs(t, "writer")
	body, _ := json.Marshal(map[string]string{"envelope": envelope})

	code, resp := f.call(t, "backoffice", "/v1/decrypt/raw", string(body))
	if code != http.StatusOK {
		t.Fatalf("the backoffice key was refused: %d %v", code, resp)
	}
	if resp["value"] != "3201012501990001" {
		t.Errorf("value = %v", resp["value"])
	}
}

func TestWriteOnlyKeyCannotReadAtAll(t *testing.T) {
	// The least-privilege credential for a form-submission service: it can
	// encrypt and index, and cannot read anything back.
	f := newScopeFixture(t)
	envelope := f.encryptAs(t, "writer")
	body, _ := json.Marshal(map[string]string{"envelope": envelope})

	for _, path := range []string{"/v1/decrypt", "/v1/decrypt/raw"} {
		code, _ := f.call(t, "writer", path, string(body))
		if code != http.StatusForbidden {
			t.Errorf("%s with a write-only key returned %d, want 403", path, code)
		}
	}
}

func TestBlindIndexScopeIsSeparate(t *testing.T) {
	f := newScopeFixture(t)

	// The writer holds blindindex; the reader does not.
	if code, _ := f.call(t, "writer", "/v1/blind-index", `{"value":"3201012501990001","kid":"`+testKID+`"}`); code != http.StatusOK {
		t.Errorf("the writer could not compute an index: %d", code)
	}
	if code, _ := f.call(t, "reader", "/v1/blind-index", `{"value":"3201012501990001","kid":"`+testKID+`"}`); code != http.StatusForbidden {
		t.Errorf("a key without blindindex returned %d, want 403", code)
	}
}

// --- the failure codes differ ---------------------------------------------

func TestMissingCredentialIs401AndMissingScopeIs403(t *testing.T) {
	// A caller needs to know which one it is: fix your credential, or ask for
	// access. Collapsing them would send people to the wrong team.
	f := newScopeFixture(t)

	noCreds, _ := f.call(t, "", "/v1/decrypt/raw", `{}`)
	if noCreds != http.StatusUnauthorized {
		t.Errorf("no credential returned %d, want 401", noCreds)
	}

	wrongScope, _ := f.call(t, "reader", "/v1/decrypt/raw", `{}`)
	if wrongScope != http.StatusForbidden {
		t.Errorf("insufficient scope returned %d, want 403", wrongScope)
	}
}
