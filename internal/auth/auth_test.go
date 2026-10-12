package auth

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"strings"
	"testing"
)

func mustHash(t *testing.T, token string) string {
	t.Helper()
	h, err := HashToken(token, DefaultParams())
	if err != nil {
		t.Fatalf("HashToken: %v", err)
	}
	return h
}

// store builds a FileStore from records, failing the test on bad input.
func store(t *testing.T, records []Record) *FileStore {
	t.Helper()
	raw, _ := json.Marshal(records)
	s, err := NewFileStore(raw)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return s
}

func certWithCN(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
}

// --- token handling -------------------------------------------------------

func TestVerifyTokenAcceptsTheRightToken(t *testing.T) {
	token, _ := GenerateToken()
	hash := mustHash(t, token)

	if !VerifyToken(token, hash) {
		t.Fatal("a correct token did not verify")
	}
}

func TestVerifyTokenRejectsEverythingElse(t *testing.T) {
	token, _ := GenerateToken()
	hash := mustHash(t, token)

	cases := map[string]string{
		"a different token":     "panda_svc_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"a prefix of the token": token[:len(token)-1],
		"the empty string":      "",
		"a malformed hash":      "not json at all",
		"an empty hash":         "{}",
	}

	for name, candidate := range cases {
		if VerifyToken(candidate, hash) {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestTokensAreLongEnoughToResistGuessing(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !strings.HasPrefix(token, KeyPrefix) {
		t.Errorf("token does not carry the service prefix: %q", token)
	}
	if len(token) < MinTokenLength {
		t.Errorf("token is only %d characters", len(token))
	}
}

func TestShortTokensAreRejectedWithoutHashing(t *testing.T) {
	// Every request with a short candidate would otherwise cost a full
	// Argon2id verification, turning the auth path into a CPU exhaustion
	// vector. The length floor is what keeps that off the expensive path.
	if VerifyToken("short", mustHash(t, "panda_svc_"+strings.Repeat("a", 40))) {
		t.Fatal("a short token was accepted")
	}
}

func TestStoreRejectsMalformedRecords(t *testing.T) {
	cases := map[string]string{
		"no id":        `[{"hash":"x","scopes":["decrypt"]}]`,
		"no hash":      `[{"id":"a","scopes":["decrypt"]}]`,
		"bad scope":    `[{"id":"a","hash":"x","scopes":["superuser"]}]`,
		"duplicate id": `[{"id":"a","hash":"x","scopes":[]},{"id":"a","hash":"y","scopes":[]}]`,
	}

	for name, raw := range cases {
		if _, err := NewFileStore([]byte(raw)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestLookupRejectsTheWrongKindOfCredential(t *testing.T) {
	token, _ := GenerateToken()
	s := store(t, []Record{{ID: "k1", Hash: mustHash(t, token), Scopes: []string{"decrypt"}}})

	// A registration token, not a service key.
	registration := "panda_live_" + strings.Repeat("a", 48)

	principal, err := s.Lookup(registration)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if principal != nil {
		t.Error("a registration token authenticated as a service key")
	}
}

func TestLookupFindsThePrincipal(t *testing.T) {
	token, _ := GenerateToken()
	s := store(t, []Record{{ID: "reader", Hash: mustHash(t, token), Scopes: []string{"decrypt"}}})

	principal, err := s.Lookup(token)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if principal == nil {
		t.Fatal("the key was not found")
	}
	if principal.KeyID != "reader" {
		t.Errorf("key id = %q", principal.KeyID)
	}
}

// --- the scope model ------------------------------------------------------

func TestDecryptDoesNotImplyUnmask(t *testing.T) {
	// The control the whole design rests on.
	principal := &Principal{KeyID: "reader", Scopes: NewScopeSet(ScopeEncrypt, ScopeDecrypt)}

	if err := Authorize(principal, "decrypt"); err != nil {
		t.Errorf("decrypt was refused: %v", err)
	}

	err := Authorize(principal, "decrypt_raw")
	if err == nil {
		t.Fatal("a decrypt-only key was allowed to unmask")
	}

	denied, ok := err.(*Denied)
	if !ok {
		t.Fatalf("expected a *Denied, got %T", err)
	}
	if denied.Unauthorized {
		t.Error("an insufficient scope was reported as unauthorised; it is a 403, not a 401")
	}
}

func TestEncryptOnlyKeyCannotReadAtAll(t *testing.T) {
	writer := &Principal{KeyID: "writer", Scopes: NewScopeSet(ScopeEncrypt, ScopeBlindIndex)}

	if err := Authorize(writer, "encrypt"); err != nil {
		t.Errorf("encrypt was refused: %v", err)
	}
	for _, op := range []string{"decrypt", "decrypt_raw"} {
		if err := Authorize(writer, op); err == nil {
			t.Errorf("a write-only key was allowed to %s", op)
		}
	}
}

func TestUnmappedOperationIsRefused(t *testing.T) {
	// A new endpoint that nobody mapped must not be reachable by default.
	all := &Principal{KeyID: "admin", Scopes: NewScopeSet(AllScopes...)}

	if err := Authorize(all, "something_added_later"); err == nil {
		t.Fatal("an operation with no scope mapping was allowed")
	}
}

func TestThereIsNoWildcardScope(t *testing.T) {
	if _, err := ParseScopes([]string{"*"}); err == nil {
		t.Fatal(`"*" parsed as a scope; a wildcard is how least privilege becomes an all-powerful key`)
	}
}

// --- the authenticator ----------------------------------------------------

func newAuth(t *testing.T, mode Mode) (*Authenticator, string) {
	t.Helper()
	token, _ := GenerateToken()
	s := store(t, []Record{{
		ID:       "reader",
		Hash:     mustHash(t, token),
		Scopes:   []string{"decrypt"},
		ClientCN: "opd-app",
	}})

	a, err := NewAuthenticator(s, mode)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a, token
}

func TestMTLSAndAPIKeyRequireBoth(t *testing.T) {
	a, token := newAuth(t, ModeMTLSAndAPIKey)
	ctx := context.Background()

	if _, err := a.Authenticate(ctx, Credentials{Token: token}); err == nil {
		t.Error("a valid key without a certificate authenticated")
	}
	if _, err := a.Authenticate(ctx, Credentials{ClientCert: certWithCN("opd-app")}); err == nil {
		t.Error("a certificate without a key authenticated")
	}

	result, err := a.Authenticate(ctx, Credentials{Token: token, ClientCert: certWithCN("opd-app")})
	if err != nil {
		t.Fatalf("both credentials together were refused: %v", err)
	}
	if result.ClientCN != "opd-app" {
		t.Errorf("client CN not recorded: %q", result.ClientCN)
	}
}

func TestCNPinningRejectsTheWrongCertificate(t *testing.T) {
	a, token := newAuth(t, ModeMTLSAndAPIKey)

	// The key is valid, but presented from a different certificate. A leaked
	// key should be useless without the matching certificate.
	_, err := a.Authenticate(context.Background(), Credentials{
		Token:      token,
		ClientCert: certWithCN("someone-else"),
	})
	if err == nil {
		t.Fatal("a key pinned to one CN authenticated from another")
	}
}

func TestProductionModesRefuseAnonymous(t *testing.T) {
	a, _ := newAuth(t, ModeAPIKey)

	if _, err := a.Authenticate(context.Background(), Credentials{}); err == nil {
		t.Error("no credentials authenticated in apikey mode")
	}
}

func TestNoneModeGrantsEverythingAndIsExplicit(t *testing.T) {
	// Only reachable because config.Load refuses it outside dev and behind an
	// acknowledgement variable. Asserted so the behaviour is visible.
	a, err := NewAuthenticator(nil, ModeNone)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	result, err := a.Authenticate(context.Background(), Credentials{})
	if err != nil {
		t.Fatalf("none mode refused a request: %v", err)
	}
	if !result.Principal.Can(ScopeUnmask) {
		t.Error("none mode does not grant unmask; the config gate is the only thing protecting it")
	}
}

func TestAuthenticatorRejectsAnUnknownMode(t *testing.T) {
	if _, err := NewAuthenticator(nil, Mode("trust-me")); err == nil {
		t.Fatal("an unknown auth mode was accepted")
	}
}

func TestScopeListIsStable(t *testing.T) {
	set := NewScopeSet(ScopeUnmask, ScopeEncrypt, ScopeDecrypt)
	got := strings.Join(set.List(), ",")
	if got != "encrypt,decrypt,unmask" {
		t.Errorf("scope list = %q, want a stable declared order", got)
	}
}
