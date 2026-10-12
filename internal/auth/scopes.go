// Package auth holds API-key verification and the scope model.
//
// The scope model is the single most important control in this service. A
// network-reachable decryption endpoint with one all-powerful credential is a
// bulk plaintext exfiltration path; the same endpoint with a credential that
// can only encrypt is a write-only utility. The difference is entirely whether
// `unmask` is separable — so it is a scope of its own, not a modifier on
// `decrypt`.
package auth

import "fmt"

// Scope is one permitted operation.
type Scope string

const (
	ScopeEncrypt    Scope = "encrypt"
	ScopeDecrypt    Scope = "decrypt"
	ScopeUnmask     Scope = "unmask"
	ScopeMask       Scope = "mask"
	ScopeBlindIndex Scope = "blindindex"
	ScopeKeysRead   Scope = "keys:read"
	ScopeKeysRotate Scope = "keys:rotate"
	ScopeKeysShred  Scope = "keys:shred"
)

// AllScopes is the full set, used only by tests and by the config validator.
// There is deliberately no wildcard scope: `*` is how a least-privilege design
// becomes an all-powerful credential in one careless edit.
var AllScopes = []Scope{
	ScopeEncrypt,
	ScopeDecrypt,
	ScopeUnmask,
	ScopeMask,
	ScopeBlindIndex,
	ScopeKeysRead,
	ScopeKeysRotate,
	ScopeKeysShred,
}

func (s Scope) Valid() bool {
	for _, known := range AllScopes {
		if s == known {
			return true
		}
	}
	return false
}

// ScopeSet is a set of granted scopes.
type ScopeSet map[Scope]struct{}

func NewScopeSet(scopes ...Scope) ScopeSet {
	set := make(ScopeSet, len(scopes))
	for _, s := range scopes {
		set[s] = struct{}{}
	}
	return set
}

func ParseScopes(raw []string) (ScopeSet, error) {
	set := make(ScopeSet, len(raw))
	for _, r := range raw {
		s := Scope(r)
		if !s.Valid() {
			return nil, fmt.Errorf("unknown scope %q", r)
		}
		set[s] = struct{}{}
	}
	return set, nil
}

func (s ScopeSet) Has(scope Scope) bool {
	_, ok := s[scope]
	return ok
}

// List returns the scopes in a stable order, for logging and responses.
func (s ScopeSet) List() []string {
	out := make([]string, 0, len(s))
	for _, known := range AllScopes {
		if s.Has(known) {
			out = append(out, string(known))
		}
	}
	return out
}

// Principal is an authenticated caller.
type Principal struct {
	// KeyID identifies the credential. It is never the credential itself, so
	// it is safe in a log line and in an audit record.
	KeyID  string
	Scopes ScopeSet
	// ClientCN optionally pins this key to a client-certificate Common Name.
	//
	// When set, the key only works from a connection presenting that
	// certificate. That turns a leaked API key from a usable credential into
	// an unusable one, because the attacker also needs the certificate —
	// which is why enabling it is worth the small operational cost.
	ClientCN string
}

// Can reports whether the principal holds a scope.
func (p *Principal) Can(scope Scope) bool {
	if p == nil {
		return false
	}
	return p.Scopes.Has(scope)
}

// ScopeForOperation maps a service operation to the scope it requires.
//
// Note `decrypt_raw` requires `unmask` and not `decrypt`. A caller holding
// only `decrypt` can read masked values and cannot reach the full plaintext,
// even though both operations share the same underlying envelope.
func ScopeForOperation(operation string) Scope {
	switch operation {
	case "encrypt":
		return ScopeEncrypt
	case "decrypt":
		return ScopeDecrypt
	case "decrypt_raw":
		return ScopeUnmask
	case "mask":
		return ScopeMask
	case "blind_index":
		return ScopeBlindIndex
	case "keys_list":
		return ScopeKeysRead
	case "keys_rotate":
		return ScopeKeysRotate
	case "keys_shred":
		return ScopeKeysShred
	default:
		// An operation with no mapping cannot be authorised. Returning a
		// permissive default here would mean a new endpoint ships unguarded.
		return Scope("__unknown__")
	}
}
