package apierr

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jatimprovcsirt/panda-go/crypto"
)

func TestFromSDKMapsEverySentinel(t *testing.T) {
	cases := []struct {
		sdk  error
		want Code
	}{
		{crypto.ErrMalformedEnvelope, CodeMalformedEnvelope},
		{crypto.ErrAuthenticationFailed, CodeAuthFailed},
		{crypto.ErrKeyNotFound, CodeUnknownKID},
		{crypto.ErrUnsupportedVersion, CodeMalformedEnvelope},
		{crypto.ErrUnsupportedAlgorithm, CodeMalformedEnvelope},
	}

	for _, c := range cases {
		t.Run(string(c.want), func(t *testing.T) {
			got := FromSDK(c.sdk)
			if got.Code != c.want {
				t.Errorf("code = %q, want %q", got.Code, c.want)
			}
		})
	}
}

func TestFromSDKUnwrapsWrappedSentinels(t *testing.T) {
	// The SDK wraps its sentinels with context, so a mapping that only
	// compared with == would classify real errors as internal.
	wrapped := fmt.Errorf("%w: missing required fields", crypto.ErrMalformedEnvelope)

	if got := FromSDK(wrapped).Code; got != CodeMalformedEnvelope {
		t.Errorf("code = %q, want %q", got, CodeMalformedEnvelope)
	}
}

func TestUnknownErrorsBecomeInternal(t *testing.T) {
	// A new SDK error must surface as a bug to investigate, not be filed
	// under a category that suggests the caller did something wrong.
	got := FromSDK(errors.New("something new and unexplained"))
	if got.Code != CodeInternal {
		t.Errorf("code = %q, want %q", got.Code, CodeInternal)
	}
}

func TestFromSDKOnNilReturnsNil(t *testing.T) {
	if FromSDK(nil) != nil {
		t.Error("FromSDK(nil) returned an error")
	}
}

func TestHTTPStatusMapping(t *testing.T) {
	cases := []struct {
		code Code
		want int
	}{
		{CodeMalformedEnvelope, http.StatusBadRequest},
		{CodeAuthFailed, http.StatusBadRequest},
		{CodeUnknownKID, http.StatusBadRequest},
		{CodeInvalidPlaintext, http.StatusBadRequest},
		{CodeUnauthorized, http.StatusUnauthorized},
		{CodeForbidden, http.StatusForbidden},
		{CodeShredDisabled, http.StatusForbidden},
		{CodeNotFound, http.StatusNotFound},
		{CodePayloadTooLarge, http.StatusRequestEntityTooLarge},
		{CodeRateLimited, http.StatusTooManyRequests},
		{CodeKeyProviderUnavailable, http.StatusServiceUnavailable},
		{CodeInternal, http.StatusInternalServerError},
	}

	for _, c := range cases {
		if got := HTTPStatus(c.code); got != c.want {
			t.Errorf("HTTPStatus(%q) = %d, want %d", c.code, got, c.want)
		}
	}
}

func TestUnknownCodeFallsBackTo500(t *testing.T) {
	// A code added without a status mapping must not silently become 200.
	if got := HTTPStatus(Code("invented-later")); got != http.StatusInternalServerError {
		t.Errorf("HTTPStatus(unknown) = %d, want 500", got)
	}
}

// --- messages must be safe to return --------------------------------------

func TestSDKMessagesAreNotPassedThrough(t *testing.T) {
	// The SDK's own message could carry a KID, a path, or a provider's
	// internals. Only the service's wording reaches a caller.
	leaky := fmt.Errorf("%w: key path /etc/panda/keys/opd-dukcapil.pem not readable",
		crypto.ErrKeyNotFound)

	msg := MessageOf(FromSDK(leaky))
	if strings.Contains(msg, "/etc/panda/keys") {
		t.Fatalf("message leaks an internal path: %q", msg)
	}
}

func TestUnknownErrorGetsAGenericMessage(t *testing.T) {
	msg := MessageOf(errors.New("internal detail nobody should see"))
	if strings.Contains(msg, "internal detail") {
		t.Fatalf("unknown error leaked its message: %q", msg)
	}
}

func TestCodeOfDefaultsToInternal(t *testing.T) {
	if got := CodeOf(errors.New("anything")); got != CodeInternal {
		t.Errorf("code = %q, want %q", got, CodeInternal)
	}
}

func TestWrappedErrorKeepsItsCause(t *testing.T) {
	cause := errors.New("the underlying problem")
	err := Wrap(CodeInternal, "a safe message", cause)

	if !errors.Is(err, cause) {
		t.Error("the cause was lost")
	}
	if !strings.Contains(err.Error(), "the underlying problem") {
		t.Error("the cause is not in the error string, so logs will not show it")
	}
	if strings.Contains(MessageOf(err), "the underlying problem") {
		t.Error("the cause reached the caller-safe message")
	}
}
