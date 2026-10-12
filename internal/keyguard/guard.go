// Package keyguard wraps a key provider with a bounded cache and an explicit
// freshness check.
//
// The requirement it exists for: when the key provider becomes unreachable,
// the service must return 503 rather than an answer. For most reads a short
// window of cached keys is an acceptable trade — the alternative is that a
// thirty-second Vault blip takes down every application that depends on this
// service.
//
// For the unmask path it is not acceptable. A value decrypted under a key that
// has been revoked, or under one the provider would now refuse to serve, is
// exactly the case a revocation was performed to prevent. So the unmask path
// checks reachability first and refuses rather than falling back.
//
// That check is the reason this wrapper exists rather than relying on the
// SDK's own cache: the SDK has no way to know which operation is asking.
package keyguard

import (
	"errors"
	"os"
	"sync"
	"time"

	"github.com/jatimprovcsirt/panda-go/crypto"
)

// ErrUnavailable is returned when no key can be served.
var ErrUnavailable = errors.New("keyguard: the key provider is unavailable")

// Provider is the read path this wrapper exposes.
type Provider interface {
	crypto.KeyProvider
	// Reachable reports whether the provider answered a live request.
	//
	// Called before an unmask so that path never proceeds on cached material.
	// Kept separate from GetKey because GetKey is allowed to answer from cache,
	// and the whole point here is a call that is not allowed to.
	Reachable() bool
}

type entry struct {
	key       []byte
	fetchedAt time.Time
}

// Guarded wraps a provider with a TTL cache.
type Guarded struct {
	inner    crypto.KeyProvider
	ttl      time.Duration
	maxStale time.Duration

	mu    sync.RWMutex
	cache map[string]entry

	// probeKID exercises the provider during a reachability check. Any key id
	// would do; the configured default is used so an unknown-id response is
	// still recognised as the provider answering.
	probeKID string

	// now is injectable so tests do not have to sleep.
	now func() time.Time
}

// Options configures a Guarded.
type Options struct {
	Inner crypto.KeyProvider
	TTL   time.Duration
	// MaxStale is how long a key may be served past its TTL while the
	// provider is unreachable. Zero disables staleness entirely, which is the
	// recommended setting for a deployment that unmask-checks separately.
	MaxStale time.Duration
	Now      func() time.Time
	// ProbeKID is the key id used for reachability checks. Defaults to the
	// environment's PANDA_DEFAULT_KID.
	ProbeKID string
}

func New(opts Options) (*Guarded, error) {
	if opts.Inner == nil {
		return nil, errors.New("keyguard: an inner provider is required")
	}
	if opts.TTL <= 0 {
		opts.TTL = 5 * time.Minute
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	probe := opts.ProbeKID
	if probe == "" {
		probe = os.Getenv("PANDA_DEFAULT_KID")
	}
	if probe == "" {
		probe = "default-key"
	}

	return &Guarded{
		inner:    opts.Inner,
		ttl:      opts.TTL,
		maxStale: opts.MaxStale,
		cache:    make(map[string]entry),
		now:      opts.Now,
		probeKID: probe,
	}, nil
}

// GetKey serves from cache when fresh, and falls back to stale material only
// within MaxStale and only while the provider is failing.
func (g *Guarded) GetKey(kid string) ([]byte, error) {
	now := g.now()

	g.mu.RLock()
	if e, ok := g.cache[kid]; ok && now.Sub(e.fetchedAt) < g.ttl {
		key := e.key
		g.mu.RUnlock()
		return key, nil
	}
	g.mu.RUnlock()

	key, err := g.inner.GetKey(kid)
	if err == nil {
		// Return the copy the cache holds, not the provider's slice. Handing
		// back the provider's buffer means a provider that reuses it can
		// rewrite a key the caller is still holding — the first call would be
		// affected and every later one would not, which is the worst kind of
		// bug to reproduce.
		return g.store(kid, key, now), nil
	}

	// The provider failed. Serve stale material only if the operator allowed
	// a window — otherwise this is the moment the service stops answering.
	if errors.Is(err, crypto.ErrKeyNotFound) {
		// Not an outage. A key that does not exist will not exist later, and
		// serving something else for it would be worse than failing.
		return nil, err
	}

	g.mu.RLock()
	e, ok := g.cache[kid]
	g.mu.RUnlock()

	if ok && g.maxStale > 0 && now.Sub(e.fetchedAt) < g.ttl+g.maxStale {
		return e.key, nil
	}

	return nil, ErrUnavailable
}

// Reachable reports whether the provider answers a live request.
//
// Deliberately a real GetKey rather than a ping: a provider that can list
// health but not serve a key is not reachable in the sense that matters here.
// The call uses whatever KID is configured as the default, so it exercises the
// same path a real read would.
func (g *Guarded) Reachable() bool {
	_, err := g.inner.GetKey(g.probeKID)
	if err == nil {
		return true
	}
	// A missing key still proves the provider answered. Only a transport or
	// auth failure means unreachable.
	return errors.Is(err, crypto.ErrKeyNotFound)
}

// store caches a copy and returns it, so both the cache and the caller hold
// slices the provider cannot reach.
func (g *Guarded) store(kid string, key []byte, now time.Time) []byte {
	cp := make([]byte, len(key))
	copy(cp, key)

	g.mu.Lock()
	g.cache[kid] = entry{key: cp, fetchedAt: now}
	g.mu.Unlock()

	return cp
}

// Invalidate drops a cached key, so the next read fetches it again.
//
// Needed after a rotation: without it the service would keep serving the old
// key until the TTL expired, which is precisely the window rotation exists to
// close.
func (g *Guarded) Invalidate(kid string) {
	g.mu.Lock()
	delete(g.cache, kid)
	g.mu.Unlock()
}

// CachedKeys reports how many entries are held, for tests and diagnostics.
func (g *Guarded) CachedKeys() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.cache)
}
