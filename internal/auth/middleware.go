package auth

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
)

// Authenticator enforces both layers of the auth model.
//
// mTLS alone gives identity but no fine-grained authorisation, and makes
// per-application revocation a PKI operation. An API key alone is a bearer
// secret, replayable from anywhere on the network. Together, a leaked key is
// useless without a certificate and a leaked certificate is useless without
// the key — and each can be rotated independently.
type Authenticator struct {
	store Store
	// mode decides which layers are enforced.
	mode Mode
}

// Mode is the configured authentication mode.
type Mode string

const (
	ModeMTLSAndAPIKey Mode = "mtls+apikey"
	ModeMTLS          Mode = "mtls"
	ModeAPIKey        Mode = "apikey"
	ModeNone          Mode = "none"
)

func NewAuthenticator(store Store, mode Mode) (*Authenticator, error) {
	if mode == "" {
		mode = ModeMTLSAndAPIKey
	}
	switch mode {
	case ModeMTLSAndAPIKey, ModeMTLS, ModeAPIKey, ModeNone:
	default:
		return nil, errors.New("auth: unknown authentication mode " + string(mode))
	}
	if mode != ModeNone && mode != ModeMTLS && store == nil {
		return nil, errors.New("auth: an API key store is required for this mode")
	}
	return &Authenticator{store: store, mode: mode}, nil
}

// Credentials is what the transport extracted from the connection.
type Credentials struct {
	// Token is the bearer token, without its scheme prefix.
	Token string
	// ClientCert is the verified peer certificate, if the connection
	// presented one. Verified means the TLS layer already checked it against
	// the client CA — this package never sees an unverified certificate.
	ClientCert *x509.Certificate
}

// Result is a successful authentication.
type Result struct {
	Principal *Principal
	// ClientCN is the certificate's Common Name, empty when there is no
	// certificate. Recorded in the audit trail so an unmask can be attributed
	// to a person or an application, not just a key id.
	ClientCN string
}

// Denied describes why authentication failed, in terms safe to return.
type Denied struct {
	// Unauthorized is true for a missing or invalid credential (401), false
	// for a valid credential lacking a scope (403). The distinction matters
	// to a caller: one means fix your credential, the other means ask for
	// access.
	Unauthorized bool
	Reason       string
}

func (d *Denied) Error() string { return d.Reason }

// Authenticate checks both layers and returns the principal.
func (a *Authenticator) Authenticate(ctx context.Context, creds Credentials) (*Result, error) {
	if a.mode == ModeNone {
		// Explicitly insecure, and gated at config load time behind an
		// acknowledgement variable. Reaching here means an operator chose it.
		return &Result{Principal: &Principal{KeyID: "anonymous", Scopes: NewScopeSet(AllScopes...)}}, nil
	}

	// --- layer 1: certificate ---------------------------------------------
	needsCert := a.mode == ModeMTLSAndAPIKey || a.mode == ModeMTLS
	if needsCert && creds.ClientCert == nil {
		return nil, &Denied{Unauthorized: true, Reason: "a client certificate is required"}
	}

	clientCN := ""
	if creds.ClientCert != nil {
		clientCN = creds.ClientCert.Subject.CommonName
	}

	// --- layer 2: API key --------------------------------------------------
	if a.mode == ModeMTLS {
		// Certificate-only mode: the network is already zero-trust and
		// per-application keys are not yet issued. Scopes cannot be enforced
		// without a key to carry them, so this mode grants everything — which
		// is exactly why it is not permitted in production.
		return &Result{
			Principal: &Principal{KeyID: "cn:" + clientCN, Scopes: NewScopeSet(AllScopes...)},
			ClientCN:  clientCN,
		}, nil
	}

	token := strings.TrimSpace(creds.Token)
	if token == "" {
		return nil, &Denied{Unauthorized: true, Reason: "an API key is required"}
	}

	principal, err := a.store.Lookup(token)
	if err != nil {
		// The store failed. This is not a bad credential and must not be
		// reported as one — see ErrStoreUnavailable.
		return nil, err
	}
	if principal == nil {
		return nil, &Denied{Unauthorized: true, Reason: "the API key is not valid"}
	}

	// --- CN pinning --------------------------------------------------------
	if principal.ClientCN != "" && principal.ClientCN != clientCN {
		// A valid key from the wrong certificate. Reported as unauthorised
		// rather than forbidden: the credential did not authenticate for this
		// connection, which is what 401 means.
		return nil, &Denied{
			Unauthorized: true,
			Reason:       "this API key is not valid for the presented client certificate",
		}
	}

	return &Result{Principal: principal, ClientCN: clientCN}, nil
}

// Authorize checks that a principal holds the scope an operation requires.
func Authorize(principal *Principal, operation string) error {
	required := ScopeForOperation(operation)

	if !required.Valid() {
		// An operation with no scope mapping must not be reachable. Returning
		// nil here would mean a newly added endpoint ships unguarded.
		return &Denied{
			Unauthorized: false,
			Reason:       "this operation has no scope mapping and cannot be authorised",
		}
	}

	if !principal.Can(required) {
		return &Denied{
			Unauthorized: false,
			Reason:       "this API key does not hold the " + string(required) + " scope",
		}
	}
	return nil
}

// AnonymousIdentity is the KeyID used when authentication is disabled.
const AnonymousIdentity = "anonymous"
