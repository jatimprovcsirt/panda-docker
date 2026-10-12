package keyguard

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jatimprovcsirt/panda-go/crypto"
)

// fakeProvider counts calls and can be made to fail on demand.
type fakeProvider struct {
	mu       sync.Mutex
	key      []byte
	calls    int
	failing  bool
	notFound bool
}

func (f *fakeProvider) GetKey(kid string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++

	if f.failing {
		return nil, errors.New("connection refused")
	}
	if f.notFound {
		return nil, crypto.ErrKeyNotFound
	}
	return f.key, nil
}

func (f *fakeProvider) setFailing(v bool) {
	f.mu.Lock()
	f.failing = v
	f.mu.Unlock()
}

func (f *fakeProvider) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newGuard(t *testing.T, p *fakeProvider, ttl, maxStale time.Duration) (*Guarded, *time.Time) {
	t.Helper()

	now := time.Now()
	clock := &now

	g, err := New(Options{
		Inner:    p,
		TTL:      ttl,
		MaxStale: maxStale,
		ProbeKID: "testkey",
		Now:      func() time.Time { return *clock },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g, clock
}

func TestCachesWithinTTL(t *testing.T) {
	p := &fakeProvider{key: []byte("k")}
	g, clock := newGuard(t, p, time.Minute, 0)

	for i := 0; i < 5; i++ {
		if _, err := g.GetKey("testkey"); err != nil {
			t.Fatalf("GetKey: %v", err)
		}
	}
	if p.callCount() != 1 {
		t.Errorf("the provider was called %d times, want 1", p.callCount())
	}

	*clock = clock.Add(2 * time.Minute)
	if _, err := g.GetKey("testkey"); err != nil {
		t.Fatalf("GetKey after TTL: %v", err)
	}
	if p.callCount() != 2 {
		t.Errorf("the cache did not expire: %d calls", p.callCount())
	}
}

// --- the fail-closed property ---------------------------------------------

func TestProviderOutageRefusesRatherThanGuessing(t *testing.T) {
	p := &fakeProvider{key: []byte("k")}
	// No staleness allowed. This is the recommended production setting for a
	// deployment that unmask-checks separately.
	g, clock := newGuard(t, p, time.Minute, 0)

	if _, err := g.GetKey("testkey"); err != nil {
		t.Fatalf("warm-up: %v", err)
	}

	*clock = clock.Add(2 * time.Minute)
	p.setFailing(true)

	_, err := g.GetKey("testkey")
	if err == nil {
		t.Fatal("a key was served during a provider outage with staleness disabled")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("error = %v, want ErrUnavailable", err)
	}
}

func TestStaleWindowIsHonouredWhenConfigured(t *testing.T) {
	// The trade the operator is making: survive a short blip, at the cost of
	// serving keys slightly past their TTL.
	p := &fakeProvider{key: []byte("k")}
	g, clock := newGuard(t, p, time.Minute, 5*time.Minute)

	if _, err := g.GetKey("testkey"); err != nil {
		t.Fatalf("warm-up: %v", err)
	}

	*clock = clock.Add(2 * time.Minute)
	p.setFailing(true)

	if _, err := g.GetKey("testkey"); err != nil {
		t.Fatalf("stale material was not served within the window: %v", err)
	}

	// Past the window it must stop, however long the outage lasts.
	*clock = clock.Add(10 * time.Minute)
	if _, err := g.GetKey("testkey"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("stale material was served past the window: %v", err)
	}
}

func TestAMissingKeyIsNotAnOutage(t *testing.T) {
	// A key that does not exist will not exist later. Reporting it as an
	// outage would turn a misconfiguration into a flood of 503s and send the
	// operator looking at the wrong system.
	p := &fakeProvider{notFound: true}
	g, _ := newGuard(t, p, time.Minute, 5*time.Minute)

	_, err := g.GetKey("testkey")
	if !errors.Is(err, crypto.ErrKeyNotFound) {
		t.Errorf("error = %v, want ErrKeyNotFound", err)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Error("a missing key was reported as a provider outage")
	}
}

// --- reachability ---------------------------------------------------------

func TestReachableIsTrueWhenTheProviderAnswers(t *testing.T) {
	p := &fakeProvider{key: []byte("k")}
	g, _ := newGuard(t, p, time.Minute, 0)

	if !g.Reachable() {
		t.Error("a working provider reported unreachable")
	}
}

func TestReachableIsTrueForAMissingKey(t *testing.T) {
	// The provider answered; the key simply is not there. That is not an
	// outage, and treating it as one would block every unmask in a deployment
	// whose probe key is absent.
	p := &fakeProvider{notFound: true}
	g, _ := newGuard(t, p, time.Minute, 0)

	if !g.Reachable() {
		t.Error("a provider that answered was reported unreachable")
	}
}

func TestReachableIsFalseDuringAnOutage(t *testing.T) {
	p := &fakeProvider{key: []byte("k"), failing: true}
	g, _ := newGuard(t, p, time.Minute, 0)

	if g.Reachable() {
		t.Error("a failing provider reported reachable")
	}
}

func TestReachableBypassesTheCache(t *testing.T) {
	// The whole point: this call must not be answerable from cache, or the
	// unmask path would proceed on exactly the material it is meant to
	// refuse.
	p := &fakeProvider{key: []byte("k")}
	g, _ := newGuard(t, p, time.Hour, 0)

	if _, err := g.GetKey("testkey"); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	before := p.callCount()

	if !g.Reachable() {
		t.Fatal("unexpectedly unreachable")
	}
	if p.callCount() != before+1 {
		t.Error("the reachability check was answered from cache")
	}
}

// --- invalidation ---------------------------------------------------------

func TestInvalidateForcesARefetch(t *testing.T) {
	// Without this the service keeps serving a rotated-out key until the TTL
	// expires, which is the window rotation exists to close.
	p := &fakeProvider{key: []byte("old")}
	g, _ := newGuard(t, p, time.Hour, 0)

	first, _ := g.GetKey("testkey")
	if string(first) != "old" {
		t.Fatalf("warm-up returned %q", first)
	}

	p.mu.Lock()
	p.key = []byte("new")
	p.mu.Unlock()

	g.Invalidate("testkey")

	after, err := g.GetKey("testkey")
	if err != nil {
		t.Fatalf("GetKey after invalidate: %v", err)
	}
	if string(after) != "new" {
		t.Errorf("key = %q, want the new one", after)
	}
}

func TestCachedKeyIsCopied(t *testing.T) {
	// A provider may hand back a slice it reuses. A cache that aliases it
	// would serve whatever the provider wrote next.
	shared := []byte("original")
	p := &fakeProvider{key: shared}
	g, _ := newGuard(t, p, time.Hour, 0)

	first, _ := g.GetKey("testkey")
	shared[0] = 'X'

	second, _ := g.GetKey("testkey")
	if string(first) != "original" || string(second) != "original" {
		t.Errorf("the cached key was mutated through the provider's slice: %q %q", first, second)
	}
}

func TestNewRequiresAProvider(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("a guard was constructed with no provider")
	}
}
