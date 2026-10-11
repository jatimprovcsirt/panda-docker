package service

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jatimprovcsirt/panda-go/crypto"

	"github.com/jatimprovcsirt/panda-docker/internal/apierr"
)

// recordingSink captures audit records for assertions.
type recordingSink struct {
	mu      sync.Mutex
	records []AuditRecord
}

func (s *recordingSink) Record(r AuditRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r)
}

func (s *recordingSink) all() []AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AuditRecord(nil), s.records...)
}

// newTestService builds a service over a real LocalKeyProvider.
//
// A fake cipher would test the fake. The point of these tests is that the
// service and the SDK agree about what an envelope is, and only the real SDK
// can demonstrate that.
func newTestService(t *testing.T) (*Service, *recordingSink, string) {
	t.Helper()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	t.Setenv("PANDA_KEY_testkey", base64.StdEncoding.EncodeToString(key))
	t.Setenv("PANDA_DEFAULT_KID", "testkey")

	sink := &recordingSink{}
	svc, err := New(Options{
		Cipher:   crypto.NewFieldCipher(crypto.NewLocalKeyProvider(), nil, nil),
		Audit:    sink,
		IndexKey: []byte("index-key-for-tests-only-32-bytes"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc, sink, "testkey"
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	svc, _, kid := newTestService(t)

	const nik = "3201012501990001"

	result, err := svc.Encrypt(nik, kid)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if result.Version != 1 {
		t.Errorf("envelope version = %d, want 1", result.Version)
	}
	if result.KID != kid {
		t.Errorf("kid = %q, want %q", result.KID, kid)
	}
	if strings.Contains(result.Envelope, nik) {
		t.Fatal("the envelope contains the plaintext")
	}

	masked, err := svc.Decrypt(Actor{}, result.Envelope)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if masked != "32************01" {
		t.Errorf("masked = %q, want %q", masked, "32************01")
	}

	raw, err := svc.DecryptRaw(Actor{}, result.Envelope)
	if err != nil {
		t.Fatalf("DecryptRaw: %v", err)
	}
	if raw.Plaintext != nik {
		t.Errorf("raw = %q, want %q", raw.Plaintext, nik)
	}
}

func TestEncryptRejectsEmptyPlaintext(t *testing.T) {
	svc, _, kid := newTestService(t)

	_, err := svc.Encrypt("", kid)
	if err == nil {
		t.Fatal("empty plaintext was encrypted")
	}
	if got := apierr.CodeOf(err); got != apierr.CodeInvalidPlaintext {
		t.Errorf("code = %q, want %q", got, apierr.CodeInvalidPlaintext)
	}
}

// --- error mapping --------------------------------------------------------

func TestMalformedEnvelopeIsRejected(t *testing.T) {
	svc, _, _ := newTestService(t)

	for _, bad := range []string{"", "not json", "{}", `{"v":1}`} {
		t.Run(fmt.Sprintf("%q", bad), func(t *testing.T) {
			_, err := svc.Decrypt(Actor{}, bad)
			if err == nil {
				t.Fatal("malformed envelope was accepted")
			}
			if got := apierr.CodeOf(err); got != apierr.CodeMalformedEnvelope {
				t.Errorf("code = %q, want %q", got, apierr.CodeMalformedEnvelope)
			}
		})
	}
}

func TestTamperedEnvelopeFailsAuthentication(t *testing.T) {
	svc, _, kid := newTestService(t)

	result, err := svc.Encrypt("3201012501990001", kid)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Flip the ciphertext while leaving the structure valid.
	env, err := crypto.ParseEnvelope(result.Envelope)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
	raw[0] ^= 0xFF
	env.Ciphertext = base64.StdEncoding.EncodeToString(raw)
	tampered, _ := env.ToJSON()

	_, err = svc.Decrypt(Actor{}, tampered)
	if err == nil {
		t.Fatal("a tampered envelope decrypted successfully")
	}
	if got := apierr.CodeOf(err); got != apierr.CodeAuthFailed {
		t.Errorf("code = %q, want %q", got, apierr.CodeAuthFailed)
	}
}

func TestUnknownKIDIsReported(t *testing.T) {
	svc, _, kid := newTestService(t)

	result, err := svc.Encrypt("3201012501990001", kid)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	env, _ := crypto.ParseEnvelope(result.Envelope)
	env.Kid = "no-such-key"
	orphaned, _ := env.ToJSON()

	_, err = svc.Decrypt(Actor{}, orphaned)
	if err == nil {
		t.Fatal("an envelope with an unknown kid decrypted")
	}
	if got := apierr.CodeOf(err); got != apierr.CodeUnknownKID {
		t.Errorf("code = %q, want %q", got, apierr.CodeUnknownKID)
	}
}

// --- the audit distinction that motivated this layer ----------------------
//
// The probe that preceded this code found that a masked decrypt emits a
// `decrypt_raw` event on the SDK's own logger, because the SDK decrypts fully
// and then masks. So the SDK's stream cannot answer "who unmasked a value?".
// These tests pin the property that makes the service's own record usable:
// a masked read and an unmask are recorded as different operations.

func TestAuditDistinguishesMaskedFromRaw(t *testing.T) {
	svc, sink, kid := newTestService(t)

	result, err := svc.Encrypt("3201012501990001", kid)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := svc.Decrypt(Actor{APIKeyID: "reader"}, result.Envelope); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if _, err := svc.DecryptRaw(Actor{APIKeyID: "backoffice"}, result.Envelope); err != nil {
		t.Fatalf("DecryptRaw: %v", err)
	}

	var masked, raw int
	for _, r := range sink.all() {
		switch r.Operation {
		case "decrypt":
			masked++
		case "decrypt_raw":
			raw++
		}
	}

	// One of each. If the service simply forwarded the SDK's events, the
	// masked read would appear as a second decrypt_raw and an auditor could
	// not tell the two calls apart.
	if masked != 1 {
		t.Errorf("recorded %d masked decrypts, want 1", masked)
	}
	if raw != 1 {
		t.Errorf("recorded %d raw decrypts, want 1", raw)
	}
}

func TestAuditRecordsTheActorAndOutcome(t *testing.T) {
	svc, sink, kid := newTestService(t)

	result, _ := svc.Encrypt("3201012501990001", kid)
	actor := Actor{ClientCN: "opd-app", APIKeyID: "svc-1", SourceIP: "10.0.0.5", RequestID: "req-1"}

	if _, err := svc.DecryptRaw(actor, result.Envelope); err != nil {
		t.Fatalf("DecryptRaw: %v", err)
	}

	records := sink.all()
	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(records))
	}
	got := records[0]
	if got.Actor.ClientCN != "opd-app" || got.Actor.APIKeyID != "svc-1" {
		t.Errorf("actor not recorded: %+v", got.Actor)
	}
	if got.Outcome != "success" || got.KID != kid {
		t.Errorf("outcome/kid wrong: %+v", got)
	}
}

func TestAuditRecordsFailures(t *testing.T) {
	svc, sink, _ := newTestService(t)

	if _, err := svc.Decrypt(Actor{}, "not-an-envelope"); err == nil {
		t.Fatal("expected an error")
	}

	records := sink.all()
	if len(records) != 1 {
		t.Fatalf("got %d audit records, want 1", len(records))
	}
	if records[0].Outcome != "failure" {
		t.Errorf("outcome = %q, want failure", records[0].Outcome)
	}
	if records[0].ErrorCode == "" {
		t.Error("a failed operation was audited with no error code")
	}
}

// --- audit records must not carry data ------------------------------------

func TestAuditRecordsCarryNoPlaintext(t *testing.T) {
	svc, sink, kid := newTestService(t)

	const secret = "3201012501990001"
	result, _ := svc.Encrypt(secret, kid)
	_, _ = svc.DecryptRaw(Actor{RequestID: "req-1"}, result.Envelope)

	for _, r := range sink.all() {
		rendered := fmt.Sprintf("%+v", r)
		if strings.Contains(rendered, secret) {
			t.Fatalf("audit record contains the plaintext: %s", rendered)
		}
		if strings.Contains(rendered, result.Envelope) {
			t.Fatalf("audit record contains the ciphertext: %s", rendered)
		}
	}
}

// --- blind index ----------------------------------------------------------

func TestBlindIndexIsDeterministicAndKeyDependent(t *testing.T) {
	svc, _, _ := newTestService(t)

	a, err := svc.BlindIndex("3201012501990001", "testkey")
	if err != nil {
		t.Fatalf("BlindIndex: %v", err)
	}
	b, _ := svc.BlindIndex("3201012501990001", "testkey")
	if a != b {
		t.Fatal("the same value produced two different indexes")
	}

	other, _ := New(Options{
		Cipher:   crypto.NewFieldCipher(crypto.NewLocalKeyProvider(), nil, nil),
		IndexKey: []byte("a-completely-different-index-key!!"),
	})
	c, _ := other.BlindIndex("3201012501990001", "testkey")
	if a == c {
		t.Fatal("two different index keys produced the same index")
	}
}

func TestBlindIndexWithoutKeyFails(t *testing.T) {
	svc, _ := mustServiceWithoutIndexKey(t)

	_, err := svc.BlindIndex("3201012501990001", "testkey")
	if err == nil {
		t.Fatal("a blind index was computed with no index key configured")
	}
	// It must not silently fall back to a weaker index the caller cannot
	// distinguish from a correct one.
	if !strings.Contains(apierr.MessageOf(err), "index key") {
		t.Errorf("error does not explain the missing key: %v", err)
	}
}

func mustServiceWithoutIndexKey(t *testing.T) (*Service, *recordingSink) {
	t.Helper()
	key := make([]byte, 32)
	t.Setenv("PANDA_KEY_testkey", base64.StdEncoding.EncodeToString(key))

	sink := &recordingSink{}
	svc, err := New(Options{
		Cipher: crypto.NewFieldCipher(crypto.NewLocalKeyProvider(), nil, nil),
		Audit:  sink,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc, sink
}

func TestNewRequiresACipher(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("a service was constructed with no cipher")
	}
}

func TestNilAuditSinkIsTolerated(t *testing.T) {
	// A service with no sink must still work — it simply records nothing.
	// Asserted because a nil-dereference here would take down a decrypt.
	key := make([]byte, 32)
	t.Setenv("PANDA_KEY_testkey", base64.StdEncoding.EncodeToString(key))

	svc, err := New(Options{Cipher: crypto.NewFieldCipher(crypto.NewLocalKeyProvider(), nil, nil)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := svc.Encrypt("3201012501990001", "testkey")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := svc.Decrypt(Actor{}, result.Envelope); err != nil {
		t.Fatalf("Decrypt with nil sink: %v", err)
	}
}

func TestSDKVersionIsReported(t *testing.T) {
	v := SDKVersion()
	if v == "" {
		t.Fatal("SDKVersion returned an empty string")
	}
	// Under `go test` the module graph is present, so this should resolve to
	// the real dependency version rather than the unknown fallback.
	if v == "unknown" {
		t.Skip("build carries no module information; nothing to assert")
	}
	if !strings.HasPrefix(v, "v") {
		t.Errorf("SDKVersion = %q, want a Go module version", v)
	}
}

func TestDescribeMentionsTheSDK(t *testing.T) {
	svc, _, _ := newTestService(t)
	if !strings.Contains(svc.Describe(), "panda-docker") {
		t.Errorf("Describe = %q", svc.Describe())
	}
}

// Guard against a mapping that returns something other than a known code.
func TestEveryErrorHasAKnownCode(t *testing.T) {
	svc, _, _ := newTestService(t)

	for _, in := range []string{"", "{}", "garbage"} {
		_, err := svc.Decrypt(Actor{}, in)
		if err == nil {
			continue
		}
		code := apierr.CodeOf(err)
		if code == "" {
			t.Errorf("input %q produced an error with no code", in)
		}
		if apierr.HTTPStatus(code) == 0 {
			t.Errorf("code %q has no HTTP status", code)
		}
	}
}
