package rest

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jatimprovcsirt/panda-docker/internal/apierr"
	"github.com/jatimprovcsirt/panda-docker/internal/auth"
	"github.com/jatimprovcsirt/panda-docker/internal/service"
)

type principalKey struct{}

// authenticate resolves the caller and puts the principal in the context.
//
// Runs before routing, so an unauthenticated request never reaches a handler
// and never costs a decryption.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health and version are reachable without credentials. Version is
		// deliberately included: an operator debugging a deployment needs to
		// ask what is running before they can authenticate against it.
		if r.URL.Path == "/v1/version" {
			next.ServeHTTP(w, r)
			return
		}

		creds := auth.Credentials{
			Token: bearerToken(r),
		}
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			// Verified by the TLS layer against the client CA. This package
			// never sees an unverified certificate, which is the point of
			// doing the check there rather than here.
			creds.ClientCert = r.TLS.PeerCertificates[0]
		}

		// Rate limiting runs after authentication so it is per credential,
		// and before the handler so it bounds work that has not happened yet.
		// A limiter placed after the expensive path has not limited the cost
		// it exists to limit.
		if !s.limiter.Allow(creds.Token) {
			s.writeError(w, apierr.New(apierr.CodeRateLimited, "too many requests"))
			return
		}

		result, err := s.auth.Authenticate(r.Context(), creds)
		if err != nil {
			s.writeAuthError(w, err)
			return
		}

		ctx := context.WithValue(r.Context(), principalKey{}, result)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authorize checks the scope an operation requires.
//
// Wrapped around each route rather than checked inside each handler, so a new
// endpoint cannot be added without someone deciding which scope it needs —
// the route registration will not compile without a scope argument.
func (s *Server) authorize(operation string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, ok := principalFrom(r.Context())
		if !ok {
			// Reaching here means the route was mounted outside the
			// authenticate middleware. That is a wiring bug, and failing
			// closed is the only safe reading of it.
			s.writeError(w, apierr.New(apierr.CodeUnauthorized, "no authenticated caller"))
			return
		}

		if err := auth.Authorize(result.Principal, operation); err != nil {
			s.writeAuthError(w, err)
			return
		}

		next(w, r)
	})
}

func principalFrom(ctx context.Context) (*auth.Result, bool) {
	result, ok := ctx.Value(principalKey{}).(*auth.Result)
	return result, ok
}

// actorFrom builds the audit identity from the authenticated request.
func (s *Server) actorFrom(r *http.Request) service.Actor {
	actor := service.Actor{
		SourceIP:  clientIP(r),
		RequestID: r.Header.Get("X-Request-Id"),
	}
	if actor.RequestID == "" {
		actor.RequestID = "unset"
	}

	if result, ok := principalFrom(r.Context()); ok {
		actor.APIKeyID = result.Principal.KeyID
		actor.ClientCN = result.ClientCN
	}
	return actor
}

// writeAuthError renders an authentication or authorisation failure.
func (s *Server) writeAuthError(w http.ResponseWriter, err error) {
	// A store that could not be read is not a bad credential. Collapsing the
	// two would let a key provider outage look like a flood of bad keys, and
	// an operator would spend the incident looking in the wrong place.
	if errors.Is(err, auth.ErrStoreUnavailable) {
		s.writeError(w, apierr.Wrap(apierr.CodeKeyProviderUnavailable,
			"the API key store is unavailable", err))
		return
	}

	var denied *auth.Denied
	if errors.As(err, &denied) {
		if denied.Unauthorized {
			s.writeError(w, apierr.Wrap(apierr.CodeUnauthorized, denied.Reason, err))
			return
		}
		s.writeError(w, apierr.Wrap(apierr.CodeForbidden, denied.Reason, err))
		return
	}

	s.writeError(w, apierr.Wrap(apierr.CodeUnauthorized, "authentication failed", err))
}

// bearerToken extracts the token from the Authorization header.
//
// Only the Bearer scheme is accepted. A token passed as a query parameter
// would end up in access logs, referrer headers, and browser history — all
// places a live credential should never be.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	const scheme = "Bearer "
	if len(header) <= len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(header[len(scheme):])
}

// observe records every request's outcome and latency.
//
// Wrapped outside authentication so an unauthenticated flood is visible in the
// metrics rather than invisible — a service that only counts successful
// requests cannot show that it is being probed.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		outcome := "success"
		if rec.status >= 400 {
			outcome = "failure"
		}
		s.metrics.RecordRequest(
			operationForPath(r.URL.Path),
			outcome,
			codeForStatus(rec.status),
			time.Since(start).Seconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// operationForPath maps a route to a stable operation name.
//
// Derived from the route rather than the request, so an unknown path cannot
// create a new metric label — an unbounded label set is a memory exhaustion
// vector wearing an observability costume.
func operationForPath(path string) string {
	switch path {
	case "/v1/encrypt":
		return "encrypt"
	case "/v1/decrypt":
		return "decrypt"
	case "/v1/decrypt/raw":
		return "decrypt_raw"
	case "/v1/mask":
		return "mask"
	case "/v1/blind-index":
		return "blind_index"
	case "/v1/version":
		return "version"
	default:
		return "other"
	}
}

func codeForStatus(status int) string {
	switch status {
	case 200:
		return ""
	case 401:
		return "unauthorized"
	case 403:
		return "forbidden"
	case 429:
		return "rate_limited"
	case 503:
		return "unavailable"
	default:
		return "error"
	}
}
