// Package rest serves the HTTP/JSON transport.
//
// Handlers here do three things and nothing else: decode, call the service,
// encode. Every decision about what an operation means lives in
// internal/service, so the gRPC transport can make the same decisions by
// calling the same methods rather than by reimplementing them.
package rest

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jatimprovcsirt/panda-docker/internal/apierr"
	"github.com/jatimprovcsirt/panda-docker/internal/auth"
	"github.com/jatimprovcsirt/panda-docker/internal/metrics"
	"github.com/jatimprovcsirt/panda-docker/internal/ratelimit"
	"github.com/jatimprovcsirt/panda-docker/internal/service"
)

// Server holds the dependencies the handlers need.
type Server struct {
	svc             *service.Service
	log             *slog.Logger
	maxRequestBytes int64
	auth            *auth.Authenticator
	metrics         *metrics.Registry
	limiter         *ratelimit.Limiter
}

// Options configures a Server.
type Options struct {
	Service         *service.Service
	Logger          *slog.Logger
	MaxRequestBytes int64
	// Authenticator is required. A nil one is refused rather than replaced by
	// a permissive default — the failure mode of "auth not wired" must be a
	// service that will not start, not one that serves everyone.
	Authenticator *auth.Authenticator
	// Metrics and Limiter are optional; nil means the corresponding feature
	// is off. Neither is a security control, so a missing one degrades
	// observability rather than protection.
	Metrics *metrics.Registry
	Limiter *ratelimit.Limiter
}

func New(opts Options) (*Server, error) {
	if opts.Service == nil {
		return nil, errors.New("rest: service is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MaxRequestBytes <= 0 {
		opts.MaxRequestBytes = 1 << 20
	}
	if opts.Authenticator == nil {
		return nil, errors.New("rest: an authenticator is required")
	}
	return &Server{
		svc:             opts.Service,
		log:             opts.Logger,
		maxRequestBytes: opts.MaxRequestBytes,
		auth:            opts.Authenticator,
		metrics:         opts.Metrics,
		limiter:         opts.Limiter,
	}, nil
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Each route names the scope it requires. A new endpoint cannot be
	// registered without deciding that, which is the point of passing it here
	// rather than checking inside the handler.
	mux.Handle("POST /v1/encrypt", s.authorize("encrypt", s.handleEncrypt))
	mux.Handle("POST /v1/decrypt", s.authorize("decrypt", s.handleDecrypt))
	mux.Handle("POST /v1/decrypt/raw", s.authorize("decrypt_raw", s.handleDecryptRaw))
	mux.Handle("POST /v1/mask", s.authorize("mask", s.handleMask))
	mux.Handle("POST /v1/blind-index", s.authorize("blind_index", s.handleBlindIndex))
	mux.HandleFunc("GET /v1/version", s.handleVersion)

	// Anything else is a 404 in the same error shape as everything else. A
	// client that has to special-case the framework's default 404 page cannot
	// parse errors uniformly.
	mux.HandleFunc("/", s.handleNotFound)

	return s.recoverPanics(s.limitBody(s.observe(s.authenticate(mux))))
}

// --- middleware ------------------------------------------------------------

// limitBody caps the request body before any work happens.
//
// Applied at the outermost layer on purpose: a size check that runs after JSON
// decoding has already paid the cost it was meant to avoid.
func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, s.maxRequestBytes)
		next.ServeHTTP(w, r)
	})
}

// recoverPanics turns a panic into a 500 rather than a dropped connection.
//
// The stack goes to the log and never to the response — a stack trace is a map
// of the service's internals.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic in handler", "panic", rec, "path", r.URL.Path)
				s.writeError(w, apierr.New(apierr.CodeInternal, "an unexpected error occurred"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// --- responses -------------------------------------------------------------

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		// The header is already sent, so this cannot become an error response.
		// It can still be logged, which is the only remaining option.
		s.log.Error("could not encode response", "error", err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, err error) {
	code := apierr.CodeOf(err)
	body := errorBody{}
	body.Error.Code = string(code)
	body.Error.Message = apierr.MessageOf(err)

	// Rate limiting is the one error where the caller can act on a hint.
	if code == apierr.CodeRateLimited {
		w.Header().Set("Retry-After", "1")
	}

	s.writeJSON(w, apierr.HTTPStatus(code), body)
}

// decode reads and validates the request body.
func (s *Server) decode(w http.ResponseWriter, r *http.Request, into any) error {
	dec := json.NewDecoder(r.Body)
	// Reject unknown fields. A typo'd field name should be an error, not a
	// silently ignored setting — the caller meant something by it.
	dec.DisallowUnknownFields()

	if err := dec.Decode(into); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return apierr.New(apierr.CodePayloadTooLarge, "the request body is too large")
		}
		return apierr.Wrap(apierr.CodeMalformedEnvelope,
			"the request body is not valid JSON for this endpoint", err)
	}

	// A second value means the body contained more than one JSON document.
	if dec.More() {
		return apierr.New(apierr.CodeMalformedEnvelope,
			"the request body contains more than one JSON document")
	}
	return nil
}

// clientIP prefers the direct peer address.
//
// X-Forwarded-For is deliberately not trusted: it is caller-supplied, and an
// audit record that says a request came from wherever the caller claimed is
// worse than one that says nothing, because it looks authoritative.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- handlers --------------------------------------------------------------

type encryptRequest struct {
	Plaintext string `json:"plaintext"`
	KID       string `json:"kid"`
}

type encryptResponse struct {
	Envelope string `json:"envelope"`
	KID      string `json:"kid"`
	V        int    `json:"v"`
}

func (s *Server) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	var req encryptRequest
	if err := s.decode(w, r, &req); err != nil {
		s.writeError(w, err)
		return
	}

	result, err := s.svc.Encrypt(req.Plaintext, req.KID)
	if err != nil {
		s.writeError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, encryptResponse{
		Envelope: result.Envelope,
		KID:      result.KID,
		V:        result.Version,
	})
}

type envelopeRequest struct {
	Envelope string `json:"envelope"`
}

type decryptResponse struct {
	Value  string `json:"value"`
	Masked bool   `json:"masked"`
	KID    string `json:"kid"`
}

func (s *Server) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	var req envelopeRequest
	if err := s.decode(w, r, &req); err != nil {
		s.writeError(w, err)
		return
	}

	result, err := s.svc.Decrypt(s.actorFrom(r), req.Envelope)
	if err != nil {
		s.writeError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, decryptResponse{
		Value:  result.Value,
		Masked: true,
		KID:    result.KID,
	})
}

type decryptRawResponse struct {
	Value   string `json:"value"`
	Masked  bool   `json:"masked"`
	KID     string `json:"kid"`
	AuditID string `json:"audit_id"`
}

func (s *Server) handleDecryptRaw(w http.ResponseWriter, r *http.Request) {
	var req envelopeRequest
	if err := s.decode(w, r, &req); err != nil {
		s.writeError(w, err)
		return
	}

	actor := s.actorFrom(r)
	result, err := s.svc.DecryptRaw(actor, req.Envelope)
	if err != nil {
		s.writeError(w, err)
		return
	}

	// Recorded only here, on the path that actually returned a full value.
	// A masked read must never reach this line: if it did, the metric would
	// report unmasking that never happened and the alert built on it would be
	// worthless.
	s.metrics.RecordUnmask(actor.APIKeyID)

	s.writeJSON(w, http.StatusOK, decryptRawResponse{
		Value:   result.Plaintext,
		Masked:  false,
		KID:     result.KID,
		AuditID: result.AuditID,
	})
}

type maskRequest struct {
	Value string `json:"value"`
}

type maskResponse struct {
	Value string `json:"value"`
}

func (s *Server) handleMask(w http.ResponseWriter, r *http.Request) {
	var req maskRequest
	if err := s.decode(w, r, &req); err != nil {
		s.writeError(w, err)
		return
	}
	if req.Value == "" {
		s.writeError(w, apierr.New(apierr.CodeInvalidPlaintext, "value is empty"))
		return
	}

	s.writeJSON(w, http.StatusOK, maskResponse{Value: s.svc.Mask(req.Value)})
}

type blindIndexRequest struct {
	Value string `json:"value"`
	KID   string `json:"kid"`

	// How the value is normalised before it is hashed. Empty means
	// "lowercase". See service.DefaultNormalization for why that is the
	// default and "nik" is not.
	Normalization string `json:"normalization"`
}

type blindIndexResponse struct {
	Index string `json:"index"`
	KID   string `json:"kid"`

	// The mode actually applied, echoed back so a caller can confirm both
	// sides of a comparison agree rather than assume it. The failure this
	// guards against produces no error at all.
	Normalization string `json:"normalization"`
}

func (s *Server) handleBlindIndex(w http.ResponseWriter, r *http.Request) {
	var req blindIndexRequest
	if err := s.decode(w, r, &req); err != nil {
		s.writeError(w, err)
		return
	}
	if req.Value == "" {
		s.writeError(w, apierr.New(apierr.CodeInvalidPlaintext, "value is empty"))
		return
	}

	index, err := s.svc.BlindIndex(req.Value, req.KID, req.Normalization)
	if err != nil {
		s.writeError(w, err)
		return
	}

	s.writeJSON(w, http.StatusOK, blindIndexResponse{
		Index:         index,
		KID:           req.KID,
		Normalization: service.CanonicalNormalization(req.Normalization),
	})
}

type versionResponse struct {
	Service string `json:"service"`
	SDK     string `json:"sdk"`
	Time    string `json:"time"`
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, versionResponse{
		Service: s.svc.Describe(),
		SDK:     service.SDKVersion(),
		Time:    time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	// A method mismatch on a known path is reported as 404 rather than 405,
	// deliberately: a 405 confirms the path exists, which is a small amount of
	// information a caller does not need.
	s.writeError(w, apierr.New(apierr.CodeNotFound, "no such endpoint"))
}

// HealthHandler serves liveness and readiness.
//
// Plain HTTP on a separate port, independent of the API protocol, so
// Kubernetes probes work the same whether the instance serves REST or gRPC.
func HealthHandler(ready func() bool, metricsHandler http.Handler) http.Handler {
	mux := http.NewServeMux()

	// Metrics share the health port rather than the API port: they are
	// operator-facing, and the API listener should carry nothing but the API.
	// Serving them here also means they stay reachable regardless of which
	// protocol the instance speaks.
	if metricsHandler != nil {
		mux.Handle("GET /metrics", metricsHandler)
	}

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		// Liveness: the process is up. Deliberately says nothing about
		// dependencies — a key provider outage must not restart every pod.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"status":"not ready"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ready"}`)
	})

	return mux
}
