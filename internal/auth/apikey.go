package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

// KeyPrefix identifies a service credential.
//
// Deliberately distinct from the registration portal's `panda_live_` and
// `panda_demo_` tokens. Those authorise a one-time key-generation event;
// these authenticate a running service. A credential that works for the wrong
// purpose should be recognisable as the wrong kind at a glance.
const KeyPrefix = "panda_svc_"

// MinTokenLength is a floor on any token this service will even hash.
//
// Cheap first line of defence: without it, every request with a short
// attacker-chosen string costs a full Argon2id verification, which turns the
// authentication path into a CPU exhaustion vector.
const MinTokenLength = 24

// argon2Params are the hashing parameters.
//
// Recorded with each hash rather than assumed, so the parameters can be
// raised later without invalidating existing keys — a stored hash says how it
// was made, and verification uses what it says.
type argon2Params struct {
	Memory      uint32 `json:"m"`
	Iterations  uint32 `json:"t"`
	Parallelism uint8  `json:"p"`
	Salt        string `json:"salt"`
	Key         string `json:"key"`
}

// DefaultParams are the parameters new hashes are created with.
func DefaultParams() argon2Params {
	return argon2Params{Memory: 64 * 1024, Iterations: 1, Parallelism: 4}
}

// HashToken produces a storable hash of an API token.
//
// Argon2id rather than a plain digest: an API key is a password the service
// checks, and a fast hash of a high-entropy secret is still the wrong shape if
// the store ever leaks — it makes offline guessing free for any key a human
// chose rather than generated.
func HashToken(token string, params argon2Params) (string, error) {
	if token == "" {
		return "", errors.New("auth: cannot hash an empty token")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: could not generate a salt: %w", err)
	}
	if params.Memory == 0 {
		params = DefaultParams()
	}

	sum := argon2.IDKey([]byte(token), salt, params.Iterations, params.Memory, params.Parallelism, 32)

	encoded, err := json.Marshal(argon2Params{
		Memory:      params.Memory,
		Iterations:  params.Iterations,
		Parallelism: params.Parallelism,
		Salt:        base64.StdEncoding.EncodeToString(salt),
		Key:         base64.StdEncoding.EncodeToString(sum),
	})
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// VerifyToken checks a token against a stored hash.
//
// The comparison is constant-time, and a malformed stored hash is a failure
// rather than a panic — a corrupt record must lock a key out, never let one in.
func VerifyToken(token, stored string) bool {
	if len(token) < MinTokenLength {
		return false
	}

	var params argon2Params
	if err := json.Unmarshal([]byte(stored), &params); err != nil {
		return false
	}

	salt, err := base64.StdEncoding.DecodeString(params.Salt)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(params.Key)
	if err != nil || len(want) == 0 {
		return false
	}

	got := argon2.IDKey([]byte(token), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// Record is one API key as it appears in the store.
type Record struct {
	// ID identifies the credential. Safe to log; it is not the credential.
	ID string `json:"id"`
	// Hash is the Argon2id hash produced by HashToken.
	Hash string `json:"hash"`
	// Scopes granted. Additive; there is no wildcard.
	Scopes []string `json:"scopes"`
	// ClientCN pins the key to a certificate Common Name, if set.
	ClientCN string `json:"client_cn,omitempty"`
}

// Store resolves a presented token to a Principal.
type Store interface {
	// Lookup finds the principal for a token.
	//
	// Returning (nil, nil) means "no such key" — a normal outcome, not an
	// error. An error means the store itself failed, which is a 503 and must
	// not be confused with a bad credential.
	Lookup(token string) (*Principal, error)
}

// ErrStoreUnavailable is returned when the store cannot be read.
//
// Distinct from a failed lookup on purpose: a credential that is wrong is a
// 401, and a store that is down is a 503. Collapsing them would let a key
// provider outage look like a flood of bad credentials, and an operator would
// spend the incident looking in the wrong place.
var ErrStoreUnavailable = errors.New("auth: the API key store is unavailable")

// FileStore reads API keys from a JSON file.
//
// A file rather than the secret manager the encryption keys come from, because
// `crypto.KeyProvider` exposes only `GetKey` — there is no interface for
// reading a non-key secret from the same provider. That is a real limitation,
// recorded rather than worked around: until the SDK grows a secret-reading
// interface, the API keys live in a file or an environment variable, and the
// deployment mounts it from wherever the organisation keeps its secrets.
type FileStore struct {
	records []Record
}

// LoadFileStore reads a store from a JSON array of records.
func LoadFileStore(path string) (*FileStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("auth: could not read the key store: %w", err)
	}
	return NewFileStore(raw)
}

// NewFileStore parses a JSON array of records.
func NewFileStore(raw []byte) (*FileStore, error) {
	var records []Record
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, fmt.Errorf("auth: the key store is not valid JSON: %w", err)
	}

	seen := make(map[string]bool, len(records))
	for i, r := range records {
		if r.ID == "" {
			return nil, fmt.Errorf("auth: record %d has no id", i)
		}
		if seen[r.ID] {
			// A duplicate id means one of the two is not the key the operator
			// thinks it is. Refusing to start is the only safe reading.
			return nil, fmt.Errorf("auth: duplicate key id %q", r.ID)
		}
		seen[r.ID] = true

		if r.Hash == "" {
			return nil, fmt.Errorf("auth: key %q has no hash", r.ID)
		}
		if _, err := ParseScopes(r.Scopes); err != nil {
			return nil, fmt.Errorf("auth: key %q: %w", r.ID, err)
		}
	}

	return &FileStore{records: records}, nil
}

// Lookup implements Store.
func (s *FileStore) Lookup(token string) (*Principal, error) {
	if !strings.HasPrefix(token, KeyPrefix) {
		// Wrong kind of credential entirely — a registration token, or a
		// guess. Rejected before any hashing, which also keeps the cost of
		// junk traffic off the expensive path.
		return nil, nil
	}

	for _, r := range s.records {
		if !VerifyToken(token, r.Hash) {
			continue
		}
		scopes, err := ParseScopes(r.Scopes)
		if err != nil {
			// A record that parsed at load time cannot fail here, but if it
			// somehow did, denying is the only safe answer.
			return nil, nil
		}
		return &Principal{KeyID: r.ID, Scopes: scopes, ClientCN: r.ClientCN}, nil
	}

	// Note the cost: every record is verified, not just the matching one,
	// because the id is not derivable from the token. With a handful of keys
	// per deployment that is a few milliseconds; with hundreds it would need
	// an index prefix.
	return nil, nil
}

// GenerateToken produces a new API token.
//
// 32 bytes of entropy, base64url so it survives being pasted into a shell, a
// YAML file, and a URL without escaping.
func GenerateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return KeyPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}
