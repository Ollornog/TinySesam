package tinysesam

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rules for fetching the key set (spec section 5).
const (
	FetchTimeout       = 5 * time.Second // one fetch in total: connect, TLS, headers, body
	MaxJWKSBytes       = 64 << 10        // the largest body of a key set document
	jwksDefaultFresh   = 300             // seconds, when Cache-Control has no readable max-age
	jwksMinFresh       = 60
	jwksMaxFresh       = 3600
	jwksStaleMax       = 3600 // a set more than this past its freshness is no longer used
	jwksMinInterval    = 10   // at most one fetch attempt per this many seconds
	maxRedirectsToSame = 3
)

var maxAgeRE = regexp.MustCompile(`(?i)(?:^|,)\s*max-age\s*=\s*([0-9]+)\s*(?:,|$)`)

// fetchResult is the answer of one fetch attempt.
type fetchResult struct {
	status       int
	cacheControl string
	body         []byte
	err          error
}

// fetcher performs one fetch; it must return within FetchTimeout.
type fetcher func(ctx context.Context) fetchResult

// jwksCache keeps the last good key set and decides when to fetch. No request waits longer than FetchTimeout: a
// request that needs keys while a fetch is running shares its result.
type jwksCache struct {
	fetch fetcher
	wait  time.Duration // the longest a request waits for a running fetch

	mu          sync.Mutex
	keys        *KeySet
	freshUntil  int64
	attempted   bool
	lastAttempt int64
	running     chan struct{} // closed when the running fetch has finished; nil when none runs
}

func newJWKSCache(f fetcher) *jwksCache {
	return &jwksCache{fetch: f, wait: FetchTimeout}
}

// lookup returns the key for kid at time now (spec section 5, rule 6).
func (c *jwksCache) lookup(ctx context.Context, kid string, now int64) (ed25519.PublicKey, error) {
	fetched := false
	c.mu.Lock()
	stale := c.keys == nil || now >= c.freshUntil
	c.mu.Unlock()
	if stale {
		fetched = c.maybeFetch(ctx, now)
	}
	c.mu.Lock()
	keys, freshUntil := c.keys, c.freshUntil
	c.mu.Unlock()
	if keys == nil || now >= freshUntil+jwksStaleMax {
		return nil, refuseKid(ClassKeyUnavailable, kid, "no usable key set")
	}
	if pub := keys.lookup(kid); pub != nil {
		return pub, nil
	}
	if !fetched && c.maybeFetch(ctx, now) {
		c.mu.Lock()
		keys = c.keys
		c.mu.Unlock()
		if pub := keys.lookup(kid); pub != nil {
			return pub, nil
		}
	}
	return nil, refuseKid(ClassKid, kid, "kid not in the key set")
}

// maybeFetch starts a fetch if the rate allows it, or joins the one that runs, and waits for it at most c.wait.
// It reports whether this request fetched (or shared a fetch).
func (c *jwksCache) maybeFetch(ctx context.Context, now int64) bool {
	c.mu.Lock()
	if done := c.running; done != nil {
		c.mu.Unlock()
		c.await(ctx, done)
		return true
	}
	if c.attempted && now-c.lastAttempt < jwksMinInterval {
		c.mu.Unlock()
		return false
	}
	c.attempted, c.lastAttempt = true, now
	done := make(chan struct{})
	c.running = done
	c.mu.Unlock()
	go c.run(done, now)
	c.await(ctx, done)
	return true
}

func (c *jwksCache) await(ctx context.Context, done chan struct{}) {
	t := time.NewTimer(c.wait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	case <-ctx.Done():
	}
}

func (c *jwksCache) run(done chan struct{}, now int64) {
	var keys *KeySet
	var fresh int64
	defer func() {
		// A panic in the fetcher must neither take the process down nor keep the fetch marked as running.
		if recover() != nil {
			keys = nil
		}
		c.mu.Lock()
		if keys != nil {
			c.keys, c.freshUntil = keys, now+fresh
		}
		c.running = nil
		c.mu.Unlock()
		close(done)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), FetchTimeout)
	defer cancel()
	keys, fresh = interpretFetch(c.fetch(ctx))
}

// interpretFetch turns a fetch result into a key set and its freshness in seconds; nil for a failed fetch (rule 4),
// which never replaces the cached set.
func interpretFetch(r fetchResult) (*KeySet, int64) {
	if r.err != nil || r.status != http.StatusOK || len(r.body) > MaxJWKSBytes {
		return nil, 0
	}
	keys, err := ParseJWKS(r.body)
	if err != nil || len(keys.kids) == 0 {
		return nil, 0
	}
	return keys, freshness(r.cacheControl)
}

// freshness reads max-age from Cache-Control (default 300 s), clamped to 60-3600 s; no-cache and no-store do not
// shorten it below 60 s.
func freshness(cacheControl string) int64 {
	fresh := int64(jwksDefaultFresh)
	if m := maxAgeRE.FindStringSubmatch(cacheControl); m != nil {
		v, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			v = jwksMaxFresh // digits that overflow int64 are a very large max-age
		}
		fresh = v
	}
	return min(max(fresh, jwksMinFresh), jwksMaxFresh)
}

var errBodyTooLarge = errors.New("key set document larger than 64 KiB")

// httpFetcher fetches the configured URL. The client is a copy of the configured one with the deadline and a
// redirect policy that never leaves the host or drops to plain http.
func httpFetcher(base *http.Client, url string) fetcher {
	client := &http.Client{}
	if base != nil {
		*client = *base
	}
	if client.Timeout == 0 || client.Timeout > FetchTimeout {
		client.Timeout = FetchTimeout
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		first := via[0].URL
		if len(via) > maxRedirectsToSame || req.URL.Host != first.Host ||
			(first.Scheme == "https" && req.URL.Scheme != "https") {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return func(ctx context.Context) fetchResult {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fetchResult{err: err}
		}
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fetchResult{err: err}
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
		if err != nil {
			return fetchResult{err: err}
		}
		if len(body) > MaxJWKSBytes {
			return fetchResult{err: errBodyTooLarge}
		}
		return fetchResult{
			status:       resp.StatusCode,
			cacheControl: strings.Join(resp.Header.Values("Cache-Control"), ", "),
			body:         body,
		}
	}
}
