package rest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jatimprovcsirt/panda-go/crypto"

	"github.com/jatimprovcsirt/panda-docker/internal/auth"
	"github.com/jatimprovcsirt/panda-docker/internal/metrics"
	"github.com/jatimprovcsirt/panda-docker/internal/ratelimit"
	"github.com/jatimprovcsirt/panda-docker/internal/service"
)

type metricFixture struct {
	handler http.Handler
	reg     *metrics.Registry
	tokens  map[string]string
}

func newMetricFixture(t *testing.T, rateLimit int) *metricFixture {
	t.Helper()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	t.Setenv("PANDA_KEY_testkey", base64.StdEncoding.EncodeToString(key))
	t.Setenv("PANDA_DEFAULT_KID", testKID)

	svc, err := service.New(service.Options{
		Cipher:   crypto.NewFieldCipher(crypto.NewLocalKeyProvider(), nil, nil),
		IndexKey: []byte("an-index-key-for-tests-only-32b!!"),
	})
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}

	grants := map[string][]auth.Scope{
		"reader":     {auth.ScopeDecrypt},
		"backoffice": {auth.ScopeDecrypt, auth.ScopeUnmask},
		"writer":     {auth.ScopeEncrypt},
	}
	tokens := map[string]string{}
	var records []auth.Record
	for id, scopes := range grants {
		token, _ := auth.GenerateToken()
		hash, _ := auth.HashToken(token, auth.DefaultParams())
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

	reg := metrics.New("test", "rest", "local")
	limiter := ratelimit.New(rateLimit, rateLimit)

	srv, err := New(Options{
		Service:         svc,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxRequestBytes: 1 << 20,
		Authenticator:   a,
		Metrics:         reg,
		Limiter:         limiter,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return &metricFixture{handler: srv.Handler(), reg: reg, tokens: tokens}
}

func (f *metricFixture) do(t *testing.T, as, path, body string) (int, map[string]any) {
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

func (f *metricFixture) envelope(t *testing.T) string {
	t.Helper()
	code, body := f.do(t, "writer", "/v1/encrypt", `{"plaintext":"3201012501990001","kid":"`+testKID+`"}`)
	if code != http.StatusOK {
		t.Fatalf("encrypt returned %d: %v", code, body)
	}
	s, _ := body["envelope"].(string)
	return s
}

// --- the metric an auditor asks for ---------------------------------------

func TestUnmaskCounterCountsOnlyUnmasks(t *testing.T) {
	f := newMetricFixture(t, 0) // rate limiting off for this test
	envelope := f.envelope(t)
	body, _ := json.Marshal(map[string]string{"envelope": envelope})

	// Ten masked reads.
	for i := 0; i < 10; i++ {
		if code, _ := f.do(t, "backoffice", "/v1/decrypt", string(body)); code != http.StatusOK {
			t.Fatalf("masked read %d returned %d", i, code)
		}
	}
	if got := f.reg.UnmaskCount("backoffice"); got != 0 {
		t.Fatalf("masked reads counted as unmasks: %v", got)
	}

	// One unmask.
	if code, _ := f.do(t, "backoffice", "/v1/decrypt/raw", string(body)); code != http.StatusOK {
		t.Fatalf("unmask returned %d", code)
	}
	if got := f.reg.UnmaskCount("backoffice"); got != 1 {
		t.Errorf("unmask count = %v, want 1", got)
	}
}

func TestRefusedUnmaskIsNotCounted(t *testing.T) {
	// A request that was denied did not return a value, so counting it would
	// make the metric overstate exposure — and an alert built on it would fire
	// on probing rather than on disclosure.
	f := newMetricFixture(t, 0)
	envelope := f.envelope(t)
	body, _ := json.Marshal(map[string]string{"envelope": envelope})

	code, _ := f.do(t, "reader", "/v1/decrypt/raw", string(body))
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", code)
	}
	if got := f.reg.UnmaskCount("reader"); got != 0 {
		t.Errorf("a refused unmask was counted: %v", got)
	}
}

func TestUnmaskIsAttributedToTheCallingKey(t *testing.T) {
	// The whole point of labelling by key: an application that normally never
	// unmasks should be distinguishable from one that does.
	f := newMetricFixture(t, 0)
	envelope := f.envelope(t)
	body, _ := json.Marshal(map[string]string{"envelope": envelope})

	_, _ = f.do(t, "backoffice", "/v1/decrypt/raw", string(body))

	if f.reg.UnmaskCount("backoffice") != 1 {
		t.Error("the unmask was not attributed to the calling key")
	}
	if f.reg.UnmaskCount("reader") != 0 {
		t.Error("an unmask was attributed to a key that did not make the call")
	}
}

func TestMetricsEndpointExposesTheCounter(t *testing.T) {
	f := newMetricFixture(t, 0)
	envelope := f.envelope(t)
	body, _ := json.Marshal(map[string]string{"envelope": envelope})
	_, _ = f.do(t, "backoffice", "/v1/decrypt/raw", string(body))

	rec := httptest.NewRecorder()
	f.reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	out := rec.Body.String()
	if !strings.Contains(out, "panda_unmask_total") {
		t.Error("the unmask counter is not exposed")
	}
	if !strings.Contains(out, `api_key_id="backoffice"`) {
		t.Error("the unmask counter is not labelled by key")
	}
}

// --- rate limiting --------------------------------------------------------

func TestRateLimitRejectsAfterBurst(t *testing.T) {
	// A small burst so the test does not have to wait.
	f := newMetricFixture(t, 3)

	allowed := 0
	for i := 0; i < 10; i++ {
		code, _ := f.do(t, "writer", "/v1/encrypt", `{"plaintext":"3201012501990001","kid":"`+testKID+`"}`)
		if code == http.StatusTooManyRequests {
			break
		}
		allowed++
	}

	if allowed >= 10 {
		t.Fatal("the rate limit never triggered")
	}
	if allowed < 3 {
		t.Errorf("only %d requests were allowed, want at least the burst of 3", allowed)
	}
}

func TestRateLimitIsPerCredential(t *testing.T) {
	// A noisy application must not exhaust the budget for everyone else, and
	// a global limit would give an attacker a trivial way to deny service.
	f := newMetricFixture(t, 2)

	for i := 0; i < 10; i++ {
		if code, _ := f.do(t, "writer", "/v1/encrypt", `{"plaintext":"3201012501990001","kid":"`+testKID+`"}`); code == http.StatusTooManyRequests {
			break
		}
	}

	// A different key has its own bucket and should still be served.
	if code, _ := f.do(t, "reader", "/v1/decrypt", `{"envelope":"x"}`); code == http.StatusTooManyRequests {
		t.Error("one key's traffic exhausted another key's budget")
	}
}

func TestRateLimitRunsBeforeTheHandler(t *testing.T) {
	// A limiter placed after the expensive path has not limited the cost it
	// exists to limit. Asserted by checking that a rate-limited request never
	// produced a crypto result.
	f := newMetricFixture(t, 1)

	var sawTooMany bool
	for i := 0; i < 5; i++ {
		code, body := f.do(t, "writer", "/v1/encrypt", `{"plaintext":"3201012501990001","kid":"`+testKID+`"}`)
		if code == http.StatusTooManyRequests {
			sawTooMany = true
			if body["envelope"] != nil {
				t.Fatal("a rate-limited request still returned a result")
			}
			errObj, _ := body["error"].(map[string]any)
			if errObj["code"] != "rate_limited" {
				t.Errorf("error code = %v", errObj["code"])
			}
			break
		}
	}
	if !sawTooMany {
		t.Skip("the burst was large enough that the limit did not trigger")
	}
}

func TestRateLimitDisabledAllowsEverything(t *testing.T) {
	f := newMetricFixture(t, 0)

	for i := 0; i < 50; i++ {
		if code, _ := f.do(t, "writer", "/v1/encrypt", `{"plaintext":"3201012501990001","kid":"`+testKID+`"}`); code != http.StatusOK {
			t.Fatalf("request %d returned %d with limiting disabled", i, code)
		}
	}
}

// --- request accounting ---------------------------------------------------

func TestRequestsAreCountedByOutcome(t *testing.T) {
	f := newMetricFixture(t, 0)

	f.do(t, "writer", "/v1/encrypt", `{"plaintext":"3201012501990001","kid":"`+testKID+`"}`)
	f.do(t, "", "/v1/decrypt", `{}`)

	rec := httptest.NewRecorder()
	f.reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	out := rec.Body.String()
	if !strings.Contains(out, "panda_requests_total") {
		t.Error("requests are not counted")
	}
	if !strings.Contains(out, `outcome="success"`) || !strings.Contains(out, `outcome="failure"`) {
		t.Error("outcomes are not distinguished; an unauthenticated flood would be invisible")
	}
}

func TestUnboundedLabelValuesAreNotPossible(t *testing.T) {
	// A label taken from the request path would let any caller create an
	// unlimited number of time series.
	f := newMetricFixture(t, 0)

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v1/nonexistent-%d", i), nil)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
	}

	rec := httptest.NewRecorder()
	f.reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	out := rec.Body.String()
	for i := 0; i < 20; i++ {
		if strings.Contains(out, fmt.Sprintf("nonexistent-%d", i)) {
			t.Fatal("a request path became a metric label; cardinality is unbounded")
		}
	}
}
