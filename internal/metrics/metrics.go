// Package metrics exposes Prometheus metrics.
//
// One metric here matters more than the rest: `panda_unmask_total`, labelled
// by API key. It is what makes anomalous bulk decryption visible. An
// application that normally never calls the unmask path and suddenly starts
// doing so in a loop is the signal an OPD security team needs, and without a
// per-key counter there is nothing to alert on.
//
// Cardinality is bounded deliberately. Labels are limited to values the
// service controls — operation names, protocol, outcome, and API key ids that
// are configured rather than caller-supplied. A label taken from a request
// would let any caller create an unbounded number of time series, which is a
// memory exhaustion vector disguised as observability.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry is this service's metric registry.
//
// A dedicated registry rather than the global default, so a test can assert on
// metrics without inheriting anything another test registered.
type Registry struct {
	reg *prometheus.Registry

	requests *prometheus.CounterVec
	unmasks  *prometheus.CounterVec
	latency  *prometheus.HistogramVec
	build    *prometheus.GaugeVec

	// protocol is a label on every request counter, so it is held here rather
	// than passed at each call site — one place to be wrong instead of many.
	protocol string

	// unmaskCounts tracks per-key counts internally too, so the numbers are
	// inspectable without scraping the exposition format.
	unmaskCounts map[string]float64
}

// New builds a registry with the collectors registered.
func New(version, protocol, keyProvider string) *Registry {
	reg := prometheus.NewRegistry()

	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "panda_requests_total",
		Help: "Requests handled, by operation, protocol, outcome, and error code.",
	}, []string{"operation", "protocol", "outcome", "code"})

	unmasks := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "panda_unmask_total",
		Help: "Calls that returned a full unmasked value, by API key. This is the " +
			"metric an auditor asks for.",
	}, []string{"api_key_id"})

	latency := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "panda_request_duration_seconds",
		Help:    "Request latency by operation.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
	}, []string{"operation"})

	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "panda_build_info",
		Help: "Build information. Always 1; the labels carry the values.",
	}, []string{"version", "protocol", "key_provider"})

	reg.MustRegister(requests, unmasks, latency, build)
	build.WithLabelValues(version, protocol, keyProvider).Set(1)

	return &Registry{
		reg:          reg,
		protocol:     protocol,
		requests:     requests,
		unmasks:      unmasks,
		latency:      latency,
		build:        build,
		unmaskCounts: make(map[string]float64),
	}
}

// RecordRequest counts a handled request.
//
// The label count here must match the collector's declaration exactly. It did
// not, once: three values were passed for four labels, and because the observe
// middleware sits inside the panic-recovery middleware, the resulting panic was
// swallowed and every request counter went silently unrecorded. A metrics bug
// that presents as "no data" rather than as an error is worth a comment.
func (r *Registry) RecordRequest(operation, outcome, code string, seconds float64) {
	if r == nil {
		return
	}
	r.requests.WithLabelValues(operation, r.protocol, outcome, code).Inc()
	r.latency.WithLabelValues(operation).Observe(seconds)
}

// RecordUnmask counts a call that returned a full plaintext value.
//
// Called only from the unmask path. A masked read must never reach here —
// if it did, the metric would say an application was unmasking when it was
// only reading masked values, and the alert built on it would be worthless.
func (r *Registry) RecordUnmask(apiKeyID string) {
	if r == nil {
		return
	}
	if apiKeyID == "" {
		apiKeyID = "unknown"
	}
	r.unmasks.WithLabelValues(apiKeyID).Inc()
	r.unmaskCounts[apiKeyID]++
}

// UnmaskCount reports the in-process count for a key, for tests.
func (r *Registry) UnmaskCount(apiKeyID string) float64 {
	if r == nil {
		return 0
	}
	return r.unmaskCounts[apiKeyID]
}

// Handler serves the Prometheus exposition format.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// Nop returns a registry that records nothing.
//
// Lets a deployment turn metrics off without every call site growing a nil
// check, and lets tests construct a service without a registry.
func Nop() *Registry {
	return &Registry{unmaskCounts: map[string]float64{}}
}
