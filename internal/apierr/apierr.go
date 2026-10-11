// Package apierr defines the error contract this service exposes.
//
// The `Code` string is the contract. HTTP status and gRPC status are transport
// decoration — a client that switches between the two should not have to
// change its error handling.
//
// Where the codes come from: the SDK's typed errors are mapped here, in one
// place, rather than each transport inventing its own mapping. Two transports
// mapping the same SDK error differently is the kind of divergence that only
// shows up when a developer switches protocol and their error handling breaks.
package apierr

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/jatimprovcsirt/panda-go/crypto"
)

// Code is the machine-readable error identifier.
type Code string

const (
	CodeMalformedEnvelope      Code = "malformed_envelope"
	CodeAuthFailed             Code = "auth_failed"
	CodeUnknownKID             Code = "unknown_kid"
	CodeInvalidPlaintext       Code = "invalid_plaintext"
	CodeUnauthorized           Code = "unauthorized"
	CodeForbidden              Code = "forbidden"
	CodeNotFound               Code = "not_found"
	CodePayloadTooLarge        Code = "payload_too_large"
	CodeRateLimited            Code = "rate_limited"
	CodeKeyProviderUnavailable Code = "key_provider_unavailable"
	CodeShredDisabled          Code = "shred_disabled"
	CodeInternal               Code = "internal"
)

// Error is a service error carrying a stable code.
//
// The underlying error is retained for logging but never returned to a caller:
// it can contain a KID, a file path, or a provider's internal message.
type Error struct {
	Code    Code
	Message string
	// Cause is for the log. It is deliberately not serialised.
	Cause error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

// New builds an error from a code and a caller-safe message.
func New(code Code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Wrap attaches a cause, which is logged but never returned.
func Wrap(code Code, message string, cause error) *Error {
	return &Error{Code: code, Message: message, Cause: cause}
}

// HTTPStatus maps a code to a status.
//
// `auth_failed` and `malformed_envelope` are both 400, and they are
// deliberately distinguishable by code. AES-GCM's tag check is all-or-nothing,
// so telling a caller "the tag did not verify" reveals nothing an attacker
// could use as an oracle — and the distinction is what an operator needs when
// debugging a botched key rotation.
func HTTPStatus(code Code) int {
	switch code {
	case CodeMalformedEnvelope, CodeAuthFailed, CodeUnknownKID, CodeInvalidPlaintext:
		return http.StatusBadRequest
	case CodeUnauthorized:
		return http.StatusUnauthorized
	case CodeForbidden, CodeShredDisabled:
		return http.StatusForbidden
	case CodeNotFound:
		return http.StatusNotFound
	case CodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case CodeRateLimited:
		return http.StatusTooManyRequests
	case CodeKeyProviderUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// FromSDK maps the SDK's sentinel errors onto this service's codes.
//
// Anything unrecognised becomes `internal`, never a more specific code: a new
// SDK error should surface as a bug to investigate, not be silently filed
// under a category that suggests the caller did something wrong.
func FromSDK(err error) *Error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, crypto.ErrMalformedEnvelope):
		return Wrap(CodeMalformedEnvelope, "the envelope is not a valid PANDA envelope", err)

	case errors.Is(err, crypto.ErrAuthenticationFailed):
		// Worded to avoid confirming whether the key or the ciphertext is at
		// fault — the distinction is not useful to a caller and is useful to
		// someone probing.
		return Wrap(CodeAuthFailed, "the ciphertext failed authentication", err)

	case errors.Is(err, crypto.ErrKeyNotFound):
		return Wrap(CodeUnknownKID, "no key is available for the requested key id", err)

	case errors.Is(err, crypto.ErrUnsupportedVersion),
		errors.Is(err, crypto.ErrUnsupportedAlgorithm):
		return Wrap(CodeMalformedEnvelope, "the envelope uses a format this service does not support", err)

	default:
		return Wrap(CodeInternal, "an unexpected error occurred", err)
	}
}

// CodeOf extracts the code from an error, defaulting to `internal`.
func CodeOf(err error) Code {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return CodeInternal
}

// MessageOf extracts the caller-safe message, defaulting to a generic one.
//
// The default matters: an error that reaches here without going through
// FromSDK or New has a message that was not written for a caller, and might
// carry a path or a provider's internals.
func MessageOf(err error) string {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr.Message
	}
	return "an unexpected error occurred"
}
