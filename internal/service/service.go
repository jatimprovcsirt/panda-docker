// Package service holds the operations this container exposes.
//
// Everything transport-agnostic lives here. The REST and gRPC handlers are
// thin adapters over these methods, which is what keeps the two protocols from
// drifting apart: there is one implementation of "decrypt", not two.
//
// The service keeps its own audit record. It does not rely on the SDK's audit
// stream, and the difference matters — see Decrypt.
package service

import (
	"errors"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/jatimprovcsirt/panda-go/blindindex"
	"github.com/jatimprovcsirt/panda-go/crypto"
	"github.com/jatimprovcsirt/panda-go/masking"

	"github.com/jatimprovcsirt/panda-docker/internal/apierr"
)

// Actor is the authenticated caller, as far as the transport could determine.
//
// It is passed in rather than derived here because only the transport knows
// about client certificates and API keys.
type Actor struct {
	// ClientCN is the Common Name from the client certificate, if mTLS is on.
	ClientCN string
	// APIKeyID identifies the credential, never the credential itself.
	APIKeyID string
	// SourceIP is the caller's address for the audit record.
	SourceIP string
	// RequestID correlates the audit record with the caller's own logs.
	RequestID string
}

// AuditRecord is what this service writes for each operation.
//
// It is deliberately separate from the SDK's audit logger. The probe that
// preceded this code found that a masked decrypt emits a `decrypt_raw` event
// internally — the SDK decrypts fully and then masks — so the SDK's stream
// cannot answer "who actually unmasked a value?". Every masked read would look
// like an unmask.
//
// This record is written at the API level, where the service knows whether the
// caller asked for masked or raw. That is the distinction an auditor needs.
type AuditRecord struct {
	Operation string // "decrypt" or "decrypt_raw" — what the caller asked for
	Outcome   string // "success" or "failure"
	Actor     Actor
	KID       string
	ErrorCode apierr.Code
}

// AuditSink receives audit records. Implementations must not block.
type AuditSink interface {
	Record(AuditRecord)
}

// nopSink discards records. Used by tests and by a deployment that has not
// configured a sink; it is not a silent default in production because the
// entrypoint requires a sink to be constructed.
type nopSink struct{}

func (nopSink) Record(AuditRecord) {}

// Service exposes PANDA's operations over a transport-neutral interface.
type Service struct {
	cipher *crypto.FieldCipher
	audit  AuditSink
	// indexKey is the key used for blind indexing. It is separate from the
	// encryption keys: an index key that leaked would not expose plaintext,
	// and an encryption key that leaked would not let an attacker forge a
	// matching index.
	indexKey []byte
	keyGuard Reachability
}

// Reachability is an optional freshness check on the key provider.
//
// Implemented by internal/keyguard. Optional because a test or a deployment
// with no caching needs nothing here — but when present, the unmask path
// consults it before proceeding.
type Reachability interface {
	Reachable() bool
}

// Options configures a Service.
type Options struct {
	Cipher   *crypto.FieldCipher
	Audit    AuditSink
	IndexKey []byte
	// KeyGuard, when set, is checked before every unmask.
	KeyGuard Reachability
}

// New builds a Service. A nil audit sink is replaced by a discarding one.
func New(opts Options) (*Service, error) {
	if opts.Cipher == nil {
		return nil, errors.New("service: cipher is required")
	}
	sink := opts.Audit
	if sink == nil {
		sink = nopSink{}
	}
	return &Service{
		cipher:   opts.Cipher,
		audit:    sink,
		indexKey: opts.IndexKey,
		keyGuard: opts.KeyGuard,
	}, nil
}

// EncryptResult is what a caller gets back from Encrypt.
type EncryptResult struct {
	Envelope string
	KID      string
	Version  int
}

// Encrypt encrypts a plaintext value.
//
// An empty plaintext is rejected rather than encrypted. Encrypting "" produces
// a valid envelope for a value that means "absent", and a column full of those
// is indistinguishable from a column full of real blank values.
func (s *Service) Encrypt(plaintext, kid string) (*EncryptResult, error) {
	if plaintext == "" {
		return nil, apierr.New(apierr.CodeInvalidPlaintext, "plaintext is empty")
	}

	env, err := s.cipher.Encrypt([]byte(plaintext), kid)
	if err != nil {
		return nil, apierr.FromSDK(err)
	}

	encoded, err := env.ToJSON()
	if err != nil {
		return nil, apierr.Wrap(apierr.CodeInternal, "could not serialise the envelope", err)
	}

	return &EncryptResult{Envelope: encoded, KID: env.Kid, Version: env.V}, nil
}

// Decrypt returns the masked value and the key it was encrypted under.
//
// This is the default read path, and the reason it is the default is that a
// masked value can go straight into an API response or a log line without the
// caller having to think about it.
//
// Note what the SDK does underneath: it decrypts fully and then masks, which
// emits a `decrypt_raw` event on the SDK's own audit logger. That is why this
// service writes its own record separately — see AuditRecord.
func (s *Service) Decrypt(actor Actor, envelope string) (*DecryptResult, error) {
	env, err := crypto.ParseEnvelope(envelope)
	if err != nil {
		s.audit.Record(AuditRecord{
			Operation: "decrypt", Outcome: "failure", Actor: actor,
			ErrorCode: apierr.CodeOf(apierr.FromSDK(err)),
		})
		return nil, apierr.FromSDK(err)
	}

	plaintext, err := s.cipher.Decrypt(env)
	if err != nil {
		apiErr := apierr.FromSDK(err)
		s.audit.Record(AuditRecord{
			Operation: "decrypt", Outcome: "failure", Actor: actor,
			KID: env.Kid, ErrorCode: apiErr.Code,
		})
		return nil, apiErr
	}

	s.audit.Record(AuditRecord{
		Operation: "decrypt", Outcome: "success", Actor: actor, KID: env.Kid,
	})
	return &DecryptResult{Value: string(plaintext), KID: env.Kid}, nil
}

// DecryptResult carries the masked value and the key that produced it.
//
// The KID is returned rather than dropped because a caller investigating a
// rotation wants to know which key a value was encrypted under, and the
// alternative — re-parsing the envelope — means the caller has to know the
// wire format to ask a question the service already answered.
type DecryptResult struct {
	Value string
	KID   string
}

// DecryptRawResult carries the plaintext and the audit identifier.
type DecryptRawResult struct {
	Plaintext string
	KID       string
	// AuditID lets the caller correlate its own log with the audit record.
	AuditID string
}

// DecryptRaw returns the full plaintext.
//
// Separate from Decrypt by design, not by convenience. Every call here is a
// deliberate exposure of a citizen's data to whatever the caller does next,
// and the distinct method is what makes it visible at the call site — in
// review, in a diff, and in the audit stream.
func (s *Service) DecryptRaw(actor Actor, envelope string) (*DecryptRawResult, error) {
	// Reachability is checked before the unmask, not after.
	//
	// Everywhere else a short window of cached keys is an acceptable trade for
	// surviving a provider blip. Here it is not: a full value decrypted under
	// a key the provider would now refuse to serve is exactly what a
	// revocation was performed to prevent. So this path refuses rather than
	// falling back to cache.
	if s.keyGuard != nil && !s.keyGuard.Reachable() {
		s.audit.Record(AuditRecord{
			Operation: "decrypt_raw", Outcome: "failure", Actor: actor,
			ErrorCode: apierr.CodeKeyProviderUnavailable,
		})
		return nil, apierr.New(apierr.CodeKeyProviderUnavailable,
			"the key provider is unreachable; refusing to unmask on cached key material")
	}

	env, err := crypto.ParseEnvelope(envelope)
	if err != nil {
		s.audit.Record(AuditRecord{
			Operation: "decrypt_raw", Outcome: "failure", Actor: actor,
			ErrorCode: apierr.CodeOf(apierr.FromSDK(err)),
		})
		return nil, apierr.FromSDK(err)
	}

	plaintext, err := s.cipher.DecryptRaw(env)
	if err != nil {
		apiErr := apierr.FromSDK(err)
		s.audit.Record(AuditRecord{
			Operation: "decrypt_raw", Outcome: "failure", Actor: actor,
			KID: env.Kid, ErrorCode: apiErr.Code,
		})
		return nil, apiErr
	}

	// The audit record is written before the value is returned, so a crash
	// between the two cannot produce a disclosure with no record of it.
	s.audit.Record(AuditRecord{
		Operation: "decrypt_raw", Outcome: "success", Actor: actor, KID: env.Kid,
	})

	return &DecryptRawResult{
		Plaintext: string(plaintext),
		KID:       env.Kid,
		AuditID:   actor.RequestID,
	}, nil
}

// Mask applies PANDA's default masking to a plaintext value.
//
// For a caller that already holds a plaintext — an import pipeline, a
// migration tool — and needs the same masking the SDK applies on read.
func (s *Service) Mask(value string) string {
	return masking.Mask(value)
}

// Normalisation modes a caller may ask for.
//
// The SDK accepts these and falls back to the raw value for anything else.
// That fallback is exactly why the list is held here as well: a caller who
// mistypes a mode would otherwise get an index computed over input that was
// never normalised, which matches nothing and reports no error.
const (
	NormalizationLowercase = "lowercase"
	NormalizationNIK       = "nik"
	NormalizationTrim      = "trim"
	NormalizationNone      = "none"
)

// DefaultNormalization is what a caller gets when they do not choose.
//
// "lowercase" matches the SDKs, and it is the safe default for a reason: it
// trims and lowercases, and it cannot empty a value. "nik" strips everything
// that is not a digit, so an email or a name normalises to the empty string
// and every such value shares a single index. A caller indexing NIKs written
// with separators wants that mode; nobody should get it by accident.
const DefaultNormalization = NormalizationLowercase

// normalizationModes are the modes blindindex.Normalize acts on, aliases
// included.
var normalizationModes = map[string]bool{
	"lowercase": true,
	"email":     true,
	"digits":    true,
	"nik":       true,
	"phone":     true,
	"trim":      true,
	"none":      true,
	"raw":       true,
}

// KnownNormalization reports whether a mode is one the SDK will act on.
func KnownNormalization(mode string) bool {
	return normalizationModes[strings.ToLower(strings.TrimSpace(mode))]
}

// CanonicalNormalization resolves a mode, and its aliases, to one name.
//
// So a caller who asks for "phone" is told the index was computed with "nik",
// rather than being handed back a synonym and left to work out that the two
// are the same rule.
func CanonicalNormalization(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "":
		return DefaultNormalization
	case "email":
		return NormalizationLowercase
	case "digits", "phone":
		return NormalizationNIK
	case "raw":
		return NormalizationNone
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

// BlindIndex computes the deterministic index used for exact-match lookup.
//
// Requires an index key. Without one this returns an error rather than a
// weaker index: a blind index computed over a guessable key is not a blind
// index, and a caller would have no way to tell the difference.
//
// The normalisation mode is the caller's to choose. This used to be fixed to
// "nik" here, which meant the endpoint applied a NIK rule to whatever it was
// given: an email or a name normalised to the empty string, so every such
// value produced the same index and exact-match lookup returned nothing
// useful. It also disagreed with the SDKs, whose default is "lowercase", so a
// value indexed by an SDK and searched through this service never matched —
// silently, because an index that matches nothing is indistinguishable from a
// record that is not there.
func (s *Service) BlindIndex(value, kid, normalization string) (string, error) {
	if len(s.indexKey) == 0 {
		return "", apierr.New(apierr.CodeInternal,
			"no blind index key is configured; set the index key before using exact-match lookup")
	}

	if normalization != "" && !KnownNormalization(normalization) {
		return "", apierr.New(apierr.CodeInvalidNormalization,
			fmt.Sprintf("%q is not a normalisation mode this service recognises; "+
				"use one of lowercase, nik, trim, none", normalization))
	}

	return blindindex.Generate(value, s.indexKey, CanonicalNormalization(normalization)), nil
}

// NormaliseValue applies the SDK's normalisation without indexing.
//
// Exposed so a caller can see what the index was computed over — the usual
// reason two systems' indexes disagree is that they normalised differently.
func (s *Service) NormaliseValue(value, normalization string) string {
	return blindindex.Normalize(value, CanonicalNormalization(normalization))
}

// Describe returns a one-line summary of what this service is running.
func (s *Service) Describe() string {
	return fmt.Sprintf("panda-docker sdk=%s", SDKVersion())
}

// SDKVersion reports the version of the PANDA SDK this build links against.
//
// Read from the build's own module graph rather than hardcoded or injected.
// A hardcoded string drifts the first time somebody bumps the dependency and
// forgets; a version the service reports but does not use is worse than no
// version, because it is exactly what someone would check to decide whether an
// upgrade had landed.
//
// Returns "unknown" only when the build carries no module information — a
// `go run` in some configurations, for instance. That is honest about not
// knowing, which the previous implementation was not: it claimed to read the
// module and returned a constant.
func SDKVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	// The main module's dependency list. A `replace` directive means the
	// version field is empty and the replacement is what is actually linked,
	// so that is reported instead.
	for _, dep := range info.Deps {
		if dep.Path != sdkModulePath {
			continue
		}
		if dep.Replace != nil {
			if dep.Replace.Version != "" {
				return dep.Replace.Version + " (replaced)"
			}
			return "local replace"
		}
		if dep.Version == "" {
			return "unknown"
		}
		return dep.Version
	}

	return "unknown"
}

const sdkModulePath = "github.com/jatimprovcsirt/panda-go"
