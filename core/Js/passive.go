package jsanalyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

// ─── Step 1: Passive OSINT (Wayback Machine + Common Crawl) ──────────────────
//
// Queries public archives for historically indexed JS files on the target
// domain WITHOUT touching the live server. This reveals forgotten/deleted
// scripts that may still be accessible or contain old secrets.

// passiveDiscover runs Wayback Machine and Common Crawl queries concurrently
// and returns the deduplicated set of JS-file URLs found in archives.
func passiveDiscover(ctx context.Context, pool *ProxyPool, hostURL string) []string {
	domain := extractDomain(hostURL)
	if domain == "" {
		return nil
	}

	found := newSafeSet()
	ctx2, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	type result struct {
		urls []string
		src  string
	}
	ch := make(chan result, 2)

	go func() {
		urls, err := waybackQueryJS(ctx2, pool, domain)
		if err != nil {
			fmt.Printf("  \033[90m[passive]\033[0m  wayback: %v\n", err)
		}
		ch <- result{urls, "wayback"}
	}()

	go func() {
		urls, err := alienvaultQueryJS(ctx2, pool, domain)
		if err != nil {
			fmt.Printf("  \033[90m[passive]\033[0m  alienvault: %v\n", err)
		}
		ch <- result{urls, "alienvault"}
	}()

	for i := 0; i < 2; i++ {
		r := <-ch
		for _, u := range r.urls {
			if found.add(u) {
				fmt.Printf("  \033[90m[passive/%s]\033[0m  %s\n", r.src, u)
			}
		}
	}

	return found.keys()
}

// ─── Wayback Machine CDX API ──────────────────────────────────────────────────

// waybackQueryJS queries the Wayback Machine CDX API for JS files archived
// under the given domain. Returns absolute URLs from the archive index.
func waybackQueryJS(ctx context.Context, pool *ProxyPool, domain string) ([]string, error) {
	// CDX API docs: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
	apiURL := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey&filter=statuscode:200&limit=2000",
		url.QueryEscape(domain),
	)

	resp, err := pool.do(ctx, apiURL)
	if err != nil {
		return nil, fmt.Errorf("wayback CDX request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("wayback CDX returned %d", resp.StatusCode)
	}

	var jsURLs []string
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 8<<20)) // 8 MB cap
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if isJSURL(line) {
			if _, ok := seen[line]; !ok {
				seen[line] = struct{}{}
				jsURLs = append(jsURLs, line)
			}
		}
	}
	return jsURLs, scanner.Err()
}

// ─── AlienVault OTX passive DNS ───────────────────────────────────────────────

// alienvaultQueryJS queries AlienVault OTX URL list for JS files associated
// with the domain. No API key required for the public endpoint.
func alienvaultQueryJS(ctx context.Context, pool *ProxyPool, domain string) ([]string, error) {
	// OTX URL list endpoint
	apiURL := fmt.Sprintf(
		"https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500&page=1",
		url.QueryEscape(domain),
	)

	resp, err := pool.do(ctx, apiURL)
	if err != nil {
		return nil, fmt.Errorf("alienvault request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("alienvault returned %d", resp.StatusCode)
	}

	// OTX response shape: {"url_list": [{"url": "..."}, ...], ...}
	var data struct {
		URLList []struct {
			URL string `json:"url"`
		} `json:"url_list"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("alienvault parse: %w", err)
	}

	var jsURLs []string
	seen := make(map[string]struct{})
	for _, entry := range data.URLList {
		if isJSURL(entry.URL) {
			if _, ok := seen[entry.URL]; !ok {
				seen[entry.URL] = struct{}{}
				jsURLs = append(jsURLs, entry.URL)
			}
		}
	}
	return jsURLs, nil
}

// ─── URL helpers ──────────────────────────────────────────────────────────────

// isJSURL returns true if the URL appears to point at a JavaScript file.
func isJSURL(u string) bool {
	lower := strings.ToLower(u)
	// Keep .js, .jsx, .mjs, .ts, .tsx and query-string variants (.js?v=...)
	if strings.HasSuffix(lower, ".js") ||
		strings.HasSuffix(lower, ".jsx") ||
		strings.HasSuffix(lower, ".mjs") ||
		strings.HasSuffix(lower, ".ts") ||
		strings.HasSuffix(lower, ".tsx") {
		return true
	}
	if strings.Contains(lower, ".js?") ||
		strings.Contains(lower, ".jsx?") ||
		strings.Contains(lower, ".mjs?") {
		return true
	}
	return false
}

// extractDomain strips scheme and path, returning only the bare hostname.
func extractDomain(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	// Strip port if present
	host := u.Hostname()
	return host
}
