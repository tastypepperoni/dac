package dac

import (
	"context"
	"sync"
	"time"
)

// Cache reuses results within the limits of §6.6 and spaces out retries after
// "temperror": the first retry is not attempted for a minute and the interval
// doubles on each further temporary failure, up to one hour.
type Cache struct {
	mu        sync.Mutex
	entries   map[string]cacheEntry
	backoff   map[string]time.Duration
	lastPrune time.Time
}

type cacheEntry struct {
	res   Result
	until time.Time
}

// NewCache returns an empty cache.
func NewCache() *Cache {
	return &Cache{entries: map[string]cacheEntry{}, backoff: map[string]time.Duration{}}
}

// Get returns a reusable result for child at time now.
func (c *Cache) Get(child string, now time.Time) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[child]
	if !ok || !now.Before(e.until) {
		delete(c.entries, child)
		return Result{}, false
	}
	return e.res, true
}

// Put stores a result.  A result is kept for its Reuse duration, which the
// verifier has already bounded by the record TTLs, the HTTPS freshness
// lifetime, the confirmation's expiry and 86400 seconds.  A "temperror" is
// kept until the next retry is allowed (§6.6: not more often than once a minute).
func (c *Cache) Put(res Result, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if res.Outcome == TempError {
		b := c.backoff[res.Child]
		switch {
		case b == 0:
			b = time.Minute
		case b < time.Hour:
			b *= 2
		}
		if b > time.Hour {
			b = time.Hour
		}
		c.backoff[res.Child] = b
		c.entries[res.Child] = cacheEntry{res: res, until: now.Add(b)}
		return
	}
	delete(c.backoff, res.Child)
	reuse := res.Reuse
	if reuse > MaxReuse {
		reuse = MaxReuse
	}
	if reuse <= 0 {
		delete(c.entries, res.Child)
		return
	}
	c.entries[res.Child] = cacheEntry{res: res, until: now.Add(reuse)}
	// Drop entries that may no longer be reused, at most once a minute.
	if len(c.entries) > 100000 && now.Sub(c.lastPrune) > time.Minute {
		c.lastPrune = now
		for k, e := range c.entries {
			if !now.Before(e.until) {
				delete(c.entries, k)
				delete(c.backoff, k)
			}
		}
	}
}

// VerifyCached returns a cached result if one may be reused, and otherwise
// runs the procedure and caches its result.
func (v *Verifier) VerifyCached(ctx context.Context, c *Cache, child string) Result {
	now := v.now()
	if canon, err := CanonicalInput(child); err == nil {
		if r, ok := c.Get(canon, now); ok {
			return r
		}
	}
	r := v.Verify(ctx, child)
	c.Put(r, now)
	return r
}

// ParentLimiter spaces out the queries and requests a verifier sends for each
// parent domain (§11.11).  Interval is the minimum time between verifications
// that reach a given parent; requests that would come sooner wait.
type ParentLimiter struct {
	Interval time.Duration
	// MaxWait bounds how long a verification waits; beyond it the result is
	// "temperror".  Zero means 10 seconds.
	MaxWait time.Duration

	mu        sync.Mutex
	next      map[string]time.Time
	lastPrune time.Time
}

type errRateLimited struct{}

func (errRateLimited) Error() string { return "rate limited" }

// Wait blocks until a verification may reach parent.
func (l *ParentLimiter) Wait(ctx context.Context, parent string) error {
	l.mu.Lock()
	if l.next == nil {
		l.next = map[string]time.Time{}
	}
	now := time.Now()
	at := l.next[parent]
	if at.Before(now) {
		at = now
	}
	maxWait := l.MaxWait
	if maxWait == 0 {
		maxWait = 10 * time.Second
	}
	if at.Sub(now) > maxWait {
		l.mu.Unlock()
		return errRateLimited{}
	}
	l.next[parent] = at.Add(l.Interval)
	// Forget parents whose interval has passed, at most once a minute.
	if len(l.next) > 100000 && now.Sub(l.lastPrune) > time.Minute {
		l.lastPrune = now
		for k, t := range l.next {
			if t.Before(now) {
				delete(l.next, k)
			}
		}
	}
	l.mu.Unlock()
	t := time.NewTimer(time.Until(at))
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
