package jsanalyzer

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// ─── Proxy-aware HTTP client pool ─────────────────────────────────────────────

// proxyEntry wraps an http.Client with its origin proxy URL for logging.
type proxyEntry struct {
	client   *http.Client
	proxyURL string
}

// ProxyPool round-robins over a set of proxy-backed http.Clients.
// All brute-force and crawl requests MUST use pool.do() — this is the
// single entry point that guarantees every outbound request flows through
// a proxy (or falls back to direct if no proxies were provided).
type ProxyPool struct {
	entries []*proxyEntry
	counter atomic.Uint64
	mu      sync.Mutex
}

// NewProxyPool builds a ProxyPool from a slice of proxy URL strings
// (e.g. "socks5://127.0.0.1:9050", "http://user:pass@1.2.3.4:8080").
// If proxyURLs is empty, a single direct-connection client is used.
func NewProxyPool(proxyURLs []string, timeout time.Duration) *ProxyPool {
	pool := &ProxyPool{}

	for _, pu := range proxyURLs {
		if c := buildProxyHTTPClient(pu, timeout); c != nil {
			pool.entries = append(pool.entries, &proxyEntry{client: c, proxyURL: pu})
		}
	}

	if len(pool.entries) == 0 {
		pool.entries = []*proxyEntry{{
			client:   buildDirectHTTPClient(timeout),
			proxyURL: "direct",
		}}
	}
	return pool
}

// do executes a GET request through the next proxy in rotation.
// It always sets the default browser User-Agent so WAF heuristics
// see ordinary browser traffic for all brute-force / crawl requests.
func (p *ProxyPool) do(ctx context.Context, rawURL string) (*http.Response, error) {
	entry := p.next()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", defaultUA)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")
	return entry.client.Do(req)
}

// next picks the next entry using lock-free round-robin.
func (p *ProxyPool) next() *proxyEntry {
	idx := p.counter.Add(1) - 1
	return p.entries[int(idx)%len(p.entries)]
}

// ─── HTTP client builders ──────────────────────────────────────────────────────

func buildProxyHTTPClient(proxyURL string, timeout time.Duration) *http.Client {
	u, err := url.Parse(proxyURL)
	if err != nil || u.Host == "" {
		return nil
	}

	dialer := &net.Dialer{
		Timeout:   timeout / 2,
		KeepAlive: 30 * time.Second,
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext:     dialer.DialContext,
		MaxIdleConns:          200,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout / 2,
		ExpectContinueTimeout: 1 * time.Second,
	}

	switch {
	case strings.HasPrefix(proxyURL, "socks5://"):
		var auth *proxy.Auth
		if u.User != nil {
			pass, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pass}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, dialer)
		if err != nil {
			return nil
		}
		tr.Proxy = nil
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.Dial(network, addr)
		}

	case strings.HasPrefix(proxyURL, "http://"),
		strings.HasPrefix(proxyURL, "https://"):
		tr.Proxy = http.ProxyURL(u)

	default:
		return nil
	}

	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			r.Header.Set("User-Agent", defaultUA)
			return nil
		},
	}
}

func buildDirectHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout:   timeout / 2,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:    200,
			IdleConnTimeout: 90 * time.Second,
		},
		Timeout: timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			r.Header.Set("User-Agent", defaultUA)
			return nil
		},
	}
}

// ─── Safe concurrent URL set ──────────────────────────────────────────────────

// safeSet is a goroutine-safe string set for URL deduplication across workers.
type safeSet struct {
	mu sync.RWMutex
	m  map[string]struct{}
}

func newSafeSet() *safeSet {
	return &safeSet{m: make(map[string]struct{})}
}

// add inserts key and returns true if it was new.
func (s *safeSet) add(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[key]; ok {
		return false
	}
	s.m[key] = struct{}{}
	return true
}

func (s *safeSet) has(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.m[key]
	return ok
}

func (s *safeSet) keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	return out
}

func (s *safeSet) len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}
