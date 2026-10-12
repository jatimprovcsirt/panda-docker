// Package tlscfg builds the server's TLS configuration.
//
// Named tlscfg rather than tls because a local package called `tls` would
// shadow crypto/tls at every import site in this file.
package tlscfg

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
)

// Options describes the TLS material.
type Options struct {
	CertFile string
	KeyFile  string
	// ClientCAFile is required for mTLS. Without it the server would accept
	// any certificate, which is not mutual authentication — and it would look
	// like it was working.
	ClientCAFile      string
	RequireClientCert bool
}

// New builds a tls.Config.
//
// Certificates are loaded through GetCertificate rather than once at startup,
// so a rotation performed by cert-manager — which rewrites the files in place
// — takes effect without a restart. Loading once would mean a rotation
// silently breaks the service until someone notices and restarts it, which is
// the worst kind of outage: one caused by the security mechanism working.
func New(opts Options) (*tls.Config, error) {
	if opts.CertFile == "" || opts.KeyFile == "" {
		return nil, errors.New("tlscfg: a certificate and key are required")
	}

	loader := &reloadingCert{certFile: opts.CertFile, keyFile: opts.KeyFile}
	if _, err := loader.get(); err != nil {
		// Fail at startup rather than at the first request. A certificate that
		// does not load is a configuration error, and finding out about it
		// from production traffic is too late.
		return nil, err
	}

	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: loader.forClientHello,
	}

	if opts.ClientCAFile != "" {
		pool, err := loadCAPool(opts.ClientCAFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool

		if opts.RequireClientCert {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
		}
	} else if opts.RequireClientCert {
		return nil, errors.New(
			"tlscfg: a client CA is required to require client certificates; " +
				"without it the server would accept any certificate, which is not mutual authentication")
	}

	return cfg, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tlscfg: could not read the client CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("tlscfg: the client CA file contains no usable certificates")
	}
	return pool, nil
}

// reloadingCert caches the loaded certificate but re-reads when the files
// change.
type reloadingCert struct {
	certFile string
	keyFile  string

	mu      sync.Mutex
	cached  *tls.Certificate
	certMod int64
	keyMod  int64
}

// forClientHello adapts get to the signature tls.Config expects.
//
// The ClientHelloInfo is ignored on purpose: this service serves one
// certificate for all names. A deployment that needs SNI-based selection would
// change this method and nothing else.
func (r *reloadingCert) forClientHello(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.get()
}

func (r *reloadingCert) get() (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	certInfo, err := os.Stat(r.certFile)
	if err != nil {
		return nil, fmt.Errorf("tlscfg: could not stat the certificate: %w", err)
	}
	keyInfo, err := os.Stat(r.keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlscfg: could not stat the key: %w", err)
	}

	// Return the cached certificate while the files are unchanged. This runs
	// on every handshake, so the common path must be a stat rather than a
	// parse.
	if r.cached != nil && certInfo.ModTime().UnixNano() == r.certMod && keyInfo.ModTime().UnixNano() == r.keyMod {
		return r.cached, nil
	}

	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		// A rotation that produced a broken pair should not take down a
		// running service. If a previous certificate is cached, keep serving
		// with it and let the log show the failure — the alternative is an
		// outage caused by a bad deploy of the very thing that protects it.
		if r.cached != nil {
			return r.cached, nil
		}
		return nil, fmt.Errorf("tlscfg: could not load the certificate pair: %w", err)
	}

	r.cached = &cert
	r.certMod = certInfo.ModTime().UnixNano()
	r.keyMod = keyInfo.ModTime().UnixNano()
	return r.cached, nil
}
