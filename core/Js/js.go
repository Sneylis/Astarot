// Package jsanalyzer implements a multi-stage JavaScript discovery and analysis
// pipeline for all subdomains discovered in tmp/result.txt.
//
// Pipeline stages (run per-host, partially parallel):
//   1. Passive OSINT  – Wayback Machine CDX + AlienVault OTX
//   2. HTML Crawling  – <script src>, inline scripts, webpack manifests
//   3. Dynamic hints  – webpack chunk enumeration from the bundle content
//   4. Contextual brute – source maps, framework paths, version siblings
//   5. Recursive scan – regex inside each JS file → new JS refs + API endpoints
//   6. Post-process   – dedup, vendor tagging, secret scanning, JSON output
//
// IMPORTANT: every brute-force HTTP request is routed through ProxyPool.do()
// which enforces proxy rotation and a uniform browser User-Agent.
package jsanalyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── Entry point ──────────────────────────────────────────────────────────────

// JSAnalyzerMain reads live hosts from resultFile, runs the full pipeline for
// each host concurrently, and writes per-host JSON files plus a combined
// summary to outputDir.
//
// proxyURLs is the list of proxy strings already validated by PrepareProxies()
// in the active-brute phase (e.g. ["socks5://127.0.0.1:9050", ...]).
func JSAnalyzerMain(resultFile string, proxyURLs []string, outputDir string) {
	hosts, err := readLines(resultFile)
	if err != nil {
		fmt.Printf("  \033[91m[JS]\033[0m  Cannot read %s: %v\n", resultFile, err)
		return
	}
	if len(hosts) == 0 {
		fmt.Printf("  \033[93m[JS]\033[0m  No hosts in %s — skipping JS analysis.\n", resultFile)
		return
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("  \033[91m[JS]\033[0m  Cannot create output dir %s: %v\n", outputDir, err)
		return
	}

	pool := NewProxyPool(proxyURLs, 20*time.Second)

	fmt.Printf("  \033[90m→\033[0m  JS analysis: \033[97m%d\033[0m hosts  proxy-pool: \033[97m%d\033[0m\n",
		len(hosts), len(pool.entries))

	// Limit concurrency to avoid hammering too many hosts at once
	const maxConcurrent = 5
	sem := make(chan struct{}, maxConcurrent)

	var (
		mu      sync.Mutex
		results []HostResult
		wg      sync.WaitGroup
	)

	ctx := context.Background()

	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			res := scanHost(ctx, pool, h)

			mu.Lock()
			results = append(results, res)
			mu.Unlock()

			// Write per-host file immediately
			writeHostResult(res, outputDir)

			jsCount := len(res.JSFiles)
			secretCount := countSecrets(res.JSFiles)
			fmt.Printf("  \033[92m[JS/done]\033[0m  %-45s  js=\033[97m%d\033[0m  secrets=\033[91m%d\033[0m\n",
				h, jsCount, secretCount)
		}(host)
	}

	wg.Wait()

	// Write combined summary file
	combinedPath := filepath.Join(outputDir, "js_results.json")
	if f, err := os.Create(combinedPath); err == nil {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		f.Close()
		fmt.Printf("\n  \033[92m[JS]\033[0m  Combined results  →  \033[92m\033[1m%s\033[0m\n", combinedPath)
	}
}

// ─── Per-host pipeline ────────────────────────────────────────────────────────

func scanHost(ctx context.Context, pool *ProxyPool, hostURL string) HostResult {
	result := HostResult{
		URL:       hostURL,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	discovered := newSafeSet() // absolute JS URLs seen so far

	// ── Stage 1+2: Passive OSINT and HTML crawl in parallel ──────────────────
	var stage12 sync.WaitGroup
	stage12.Add(2)

	go func() {
		defer stage12.Done()
		for _, u := range passiveDiscover(ctx, pool, hostURL) {
			discovered.add(u)
		}
	}()

	var (
		pageBody   []byte
		pageStatus int
		pageServer string
		pageTitle  string
		pageTechs  map[string]TechInfo
	)
	go func() {
		defer stage12.Done()
		body, status, server, title, techs, crawledJS := crawlHTML(ctx, pool, hostURL)
		pageBody = body
		pageStatus = status
		pageServer = server
		pageTitle = title
		pageTechs = techs
		for _, u := range crawledJS {
			discovered.add(u)
		}
	}()

	stage12.Wait()

	result.StatusCode = pageStatus
	result.Server = pageServer
	result.Title = pageTitle
	result.Technologies = pageTechs

	// ── Stage 3: Extract webpack chunks from the page HTML/JS hints ──────────
	for _, u := range extractWebpackChunks(hostURL, pageBody) {
		discovered.add(u)
	}

	// ── Stage 4: Contextual brute-force (proxied) ─────────────────────────────
	framework := detectFramework(pageBody, pageTechs)
	bruteURLs := bruteContextual(ctx, pool, hostURL, framework, discovered.keys())
	for _, u := range bruteURLs {
		discovered.add(u)
	}

	// ── Stage 5: Recursive JS analysis (depth=recursionDepth) ────────────────
	jsFiles := recursiveScan(ctx, pool, discovered.keys(), hostURL, 0)

	// ── Stage 6: Post-process ─────────────────────────────────────────────────
	jsFiles = postProcess(jsFiles)
	result.JSFiles = jsFiles

	// Flat path list for the JS_PATH field in the output JSON
	paths := make([]string, 0, len(jsFiles))
	for _, f := range jsFiles {
		if f.Path != "" {
			paths = append(paths, f.Path)
		} else {
			paths = append(paths, f.URL)
		}
	}
	sort.Strings(paths)
	result.JSPaths = paths

	return result
}

// ─── Stage 2: HTML crawling ───────────────────────────────────────────────────

// crawlHTML fetches the host's main page and extracts:
//   - <script src="..."> references
//   - window.__INITIAL_STATE__ / globalThis configs
//   - webpack manifest JSON chunks
func crawlHTML(ctx context.Context, pool *ProxyPool, hostURL string) (
	body []byte, status int, server, title string,
	techs map[string]TechInfo, jsURLs []string,
) {
	ctx2, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	resp, err := pool.do(ctx2, hostURL)
	if err != nil {
		return nil, 0, "", "", nil, nil
	}
	defer resp.Body.Close()

	status = resp.StatusCode
	server = resp.Header.Get("Server")

	body, err = io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2 MB
	if err != nil {
		return body, status, server, "", nil, nil
	}

	title = extractTitle(body)
	techs = fingerprint(resp.Header, body)

	base := baseURL(hostURL)

	// <script src="...">
	for _, src := range reScriptSrc.FindAllSubmatch(body, -1) {
		if abs := resolveURL(base, string(src[1])); isJSURL(abs) {
			jsURLs = append(jsURLs, abs)
		}
	}

	// inline scripts: look for config/chunk map objects
	for _, inline := range reScriptInline.FindAllSubmatch(body, -1) {
		content := inline[1]
		for _, ref := range reJSPathStr.FindAllSubmatch(content, -1) {
			if abs := resolveURL(base, string(ref[1])); isJSURL(abs) {
				jsURLs = append(jsURLs, abs)
			}
		}
	}

	return body, status, server, title, techs, dedup(jsURLs)
}

// ─── Stage 3: Webpack chunk extraction ───────────────────────────────────────

// extractWebpackChunks looks for webpack chunk maps in the page HTML such as:
//   {0:"main",1:"vendors"}  or  chunkId: "abc123"
// then constructs the corresponding chunk URLs.
func extractWebpackChunks(hostURL string, body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	base := baseURL(hostURL)

	// Find the JS base path from any <script src="...chunk..."> already on page
	jsBase := ""
	for _, m := range reScriptSrc.FindAllSubmatch(body, -1) {
		p := string(m[1])
		if strings.Contains(strings.ToLower(p), "chunk") ||
			strings.Contains(strings.ToLower(p), "bundle") ||
			strings.Contains(strings.ToLower(p), "main") {
			if abs := resolveURL(base, p); abs != "" {
				jsBase = path.Dir(abs)
				break
			}
		}
	}
	if jsBase == "" {
		return nil
	}

	// e.g. {0:"abc",1:"def"} or {"vendors":"xyz"}
	chunkRe := regexp.MustCompile(`["']?(\w+)["']?\s*:\s*["']([0-9a-f]{8,})["']`)
	var urls []string
	for _, m := range chunkRe.FindAllSubmatch(body, -1) {
		chunkHash := string(m[2])
		candidates := []string{
			jsBase + "/" + chunkHash + ".js",
			jsBase + "/chunk-" + chunkHash + ".js",
			jsBase + "/" + string(m[1]) + "." + chunkHash + ".js",
		}
		urls = append(urls, candidates...)
	}
	return urls
}

// ─── Stage 4: Contextual brute-force (ALL requests via ProxyPool) ─────────────

// bruteContextual probes framework-specific and universal JS paths.
// Every single request flows through pool.do() with the default browser UA.
func bruteContextual(
	ctx context.Context,
	pool *ProxyPool,
	hostURL, framework string,
	alreadyFound []string,
) []string {
	base := baseURL(hostURL)

	// Build candidate list: framework-specific + universal default + sensitive
	seen := make(map[string]struct{})
	for _, u := range alreadyFound {
		seen[u] = struct{}{}
	}

	var paths []string
	addPaths := func(list []string) {
		for _, p := range list {
			p = strings.TrimPrefix(p, "/")
			full := base + "/" + p
			if _, ok := seen[full]; !ok {
				paths = append(paths, full)
				seen[full] = struct{}{}
			}
		}
	}

	if fw, ok := frameworkBrutePaths[framework]; ok {
		addPaths(fw)
	}
	addPaths(frameworkBrutePaths["default"])
	addPaths(sensitiveFilePaths)

	// Source-map check: for every already-known .js URL try appending .map
	for _, u := range alreadyFound {
		if isJSURL(u) {
			mapURL := u + ".map"
			if _, ok := seen[mapURL]; !ok {
				paths = append(paths, mapURL)
				seen[mapURL] = struct{}{}
			}
		}
	}

	// Version siblings: if /v1/ found in any known URL try v2, dev, old…
	for _, u := range alreadyFound {
		for _, variant := range versionVariants {
			if m := reVersionPath.FindString(u); m != "" {
				candidate := strings.Replace(u, m, "/"+variant+"/", 1)
				if _, ok := seen[candidate]; !ok {
					paths = append(paths, candidate)
					seen[candidate] = struct{}{}
				}
			}
		}
	}

	// Fire requests concurrently, limit to 20 parallel goroutines
	const workers = 20
	jobs := make(chan string, len(paths))
	for _, p := range paths {
		jobs <- p
	}
	close(jobs)

	var mu sync.Mutex
	var found []string
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetURL := range jobs {
				ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
				resp, err := pool.do(ctx2, targetURL) // ← always through proxy
				cancel()
				if err != nil {
					continue
				}
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					mu.Lock()
					found = append(found, targetURL)
					mu.Unlock()
					fmt.Printf("  \033[92m[brute]\033[0m  %s\n", targetURL)
				}
			}
		}()
	}
	wg.Wait()
	return found
}

// ─── Stage 5: Recursive JS analysis ──────────────────────────────────────────

// recursiveScan downloads each JS URL, extracts secrets / endpoints / new JS
// references, then recurses into any newly found JS files (depth-limited).
func recursiveScan(
	ctx context.Context,
	pool *ProxyPool,
	jsURLs []string,
	baseHostURL string,
	depth int,
) []JSFile {
	if depth > recursionDepth || len(jsURLs) == 0 {
		return nil
	}

	const workers = 15
	jobs := make(chan string, len(jsURLs))
	for _, u := range jsURLs {
		jobs <- u
	}
	close(jobs)

	filesCh := make(chan JSFile, len(jsURLs))
	var wg sync.WaitGroup

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for jsURL := range jobs {
				f := analyzeOneJS(ctx, pool, jsURL, baseHostURL)
				if depth == 0 {
					f.Source = classifySource(jsURL, "crawl")
				}
				filesCh <- f
			}
		}()
	}
	wg.Wait()
	close(filesCh)

	var files []JSFile
	nextLevel := newSafeSet()
	for f := range filesCh {
		files = append(files, f)
		for _, ref := range f.JSRefs {
			nextLevel.add(ref)
		}
	}

	// Remove already-processed URLs from the next level
	existing := make(map[string]struct{}, len(jsURLs))
	for _, u := range jsURLs {
		existing[u] = struct{}{}
	}
	var newURLs []string
	for _, u := range nextLevel.keys() {
		if _, ok := existing[u]; !ok {
			newURLs = append(newURLs, u)
		}
	}

	// Recurse into newly discovered JS files
	deeper := recursiveScan(ctx, pool, newURLs, baseHostURL, depth+1)
	return append(files, deeper...)
}

// analyzeOneJS downloads and analyses a single JS file.
func analyzeOneJS(ctx context.Context, pool *ProxyPool, jsURL, baseHostURL string) JSFile {
	f := JSFile{
		URL:    jsURL,
		Path:   urlToPath(jsURL, baseHostURL),
		Source: "crawl",
	}

	ctx2, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	resp, err := pool.do(ctx2, jsURL)
	if err != nil {
		return f
	}
	defer resp.Body.Close()

	f.StatusCode = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		return f
	}

	// Check for source map header
	if sm := resp.Header.Get("SourceMap"); sm != "" {
		f.HasSourceMap = true
	}
	if sm := resp.Header.Get("X-SourceMap"); sm != "" {
		f.HasSourceMap = true
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return f
	}
	f.ContentLength = int64(len(body))

	// Check for inline source-map comment: //# sourceMappingURL=...
	if reSourceMapComment.Match(body) {
		f.HasSourceMap = true
		// Also add the .map URL to JSRefs for retrieval
		f.JSRefs = append(f.JSRefs, jsURL+".map")
	}

	// Extract secrets
	f.Secrets = extractSecrets(body)

	// Extract API endpoints
	f.Endpoints = extractEndpoints(body)

	// Extract references to other JS files
	base := baseURL(baseHostURL)
	f.JSRefs = append(f.JSRefs, extractJSRefs(body, base)...)
	f.JSRefs = dedup(f.JSRefs)

	return f
}

// ─── Stage 6: Post-processing ─────────────────────────────────────────────────

func postProcess(files []JSFile) []JSFile {
	// 1. Deduplicate by URL
	seen := make(map[string]struct{})
	var unique []JSFile
	for _, f := range files {
		if _, ok := seen[f.URL]; !ok {
			seen[f.URL] = struct{}{}
			unique = append(unique, f)
		}
	}

	// 2. Tag vendor libraries
	for i, f := range unique {
		lower := strings.ToLower(f.URL)
		for _, pat := range vendorLibPatterns {
			if strings.Contains(lower, pat) {
				unique[i].IsVendor = true
				break
			}
		}
	}

	// 3. Sort: custom code first, then vendor; within each group by URL
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].IsVendor != unique[j].IsVendor {
			return !unique[i].IsVendor // custom first
		}
		return unique[i].URL < unique[j].URL
	})

	return unique
}

// extractSecrets is defined in nuclei_patterns.go

// ─── Endpoint extraction ──────────────────────────────────────────────────────

func extractEndpoints(body []byte) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(ep string) {
		if ep == "" || ep == "/" {
			return
		}
		if _, ok := seen[ep]; !ok {
			seen[ep] = struct{}{}
			out = append(out, ep)
		}
	}
	for _, m := range reAPIPath.FindAllSubmatch(body, -1) {
		add(string(m[1]))
	}
	for _, m := range reAPICall.FindAllSubmatch(body, -1) {
		add(string(m[1]))
	}
	sort.Strings(out)
	return out
}

func extractJSRefs(body []byte, base string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, m := range reJSPathStr.FindAllSubmatch(body, -1) {
		ref := string(m[1])
		if abs := resolveURL(base, ref); isJSURL(abs) {
			if _, ok := seen[abs]; !ok {
				seen[abs] = struct{}{}
				out = append(out, abs)
			}
		}
	}
	return out
}

// ─── Tech fingerprinting (minimal, for framework detection) ───────────────────

func detectFramework(body []byte, techs map[string]TechInfo) string {
	for name := range techs {
		lower := strings.ToLower(name)
		switch {
		case strings.Contains(lower, "next.js"):
			return "next"
		case strings.Contains(lower, "nuxt"):
			return "nuxt"
		case strings.Contains(lower, "react"):
			return "react"
		case strings.Contains(lower, "angular"):
			return "angular"
		case strings.Contains(lower, "vue"):
			return "vue"
		}
	}
	if len(body) > 0 {
		s := string(body)
		switch {
		case strings.Contains(s, `__NEXT_DATA__`) || strings.Contains(s, `/_next/`):
			return "next"
		case strings.Contains(s, `__NUXT__`) || strings.Contains(s, `/_nuxt/`):
			return "nuxt"
		case strings.Contains(s, `__webpack_require__`) || strings.Contains(s, `webpackChunk`):
			return "webpack"
		case strings.Contains(s, `ng-version`) || strings.Contains(s, `ng-app`):
			return "angular"
		case strings.Contains(s, `data-reactroot`) || strings.Contains(s, `__react`):
			return "react"
		case strings.Contains(s, `__vue_app__`) || strings.Contains(s, `data-v-`):
			return "vue"
		}
	}
	return "default"
}

// fingerprint does basic technology detection from HTTP headers + HTML body.
func fingerprint(headers http.Header, body []byte) map[string]TechInfo {
	techs := make(map[string]TechInfo)
	s := strings.ToLower(string(body))

	if strings.Contains(s, "__next_data__") || strings.Contains(s, "/_next/") {
		techs["Next.js"] = TechInfo{Categories: []string{"JavaScript frameworks"}}
	}
	if strings.Contains(s, "__nuxt__") || strings.Contains(s, "/_nuxt/") {
		techs["Nuxt.js"] = TechInfo{Categories: []string{"JavaScript frameworks"}}
	}
	if strings.Contains(s, "data-reactroot") || strings.Contains(s, "react-dom") {
		techs["React"] = TechInfo{Categories: []string{"JavaScript frameworks"}, Website: "https://reactjs.org"}
	}
	if strings.Contains(s, "ng-version") || strings.Contains(s, "ng-app=") {
		techs["Angular"] = TechInfo{Categories: []string{"JavaScript frameworks"}}
	}
	if strings.Contains(s, "data-v-") || strings.Contains(s, "__vue_app__") {
		techs["Vue.js"] = TechInfo{Categories: []string{"JavaScript frameworks"}}
	}
	if strings.Contains(s, "wp-content") || strings.Contains(s, "wp-includes") {
		techs["WordPress"] = TechInfo{Categories: []string{"CMS"}, Website: "https://wordpress.org"}
	}
	if server := headers.Get("Server"); server != "" {
		name := strings.SplitN(server, "/", 2)[0]
		techs[name] = TechInfo{Categories: []string{"Web servers"}}
	}
	if len(techs) == 0 {
		return nil
	}
	return techs
}

// ─── URL helpers ──────────────────────────────────────────────────────────────

// baseURL returns scheme+host (e.g. "https://example.com").
func baseURL(raw string) string {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// resolveURL resolves a possibly-relative href against a base URL.
// Returns "" if the result is not HTTP/HTTPS or is obviously invalid.
func resolveURL(base, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "//") {
		if strings.HasPrefix(href, "//") {
			u, err := url.Parse(base)
			if err == nil {
				return u.Scheme + ":" + href
			}
		}
		return ""
	}
	// Data URIs, mailto, etc.
	if strings.Contains(href[:min(10, len(href))], ":") && !strings.HasPrefix(href, "http") {
		return ""
	}
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	resolved := b.ResolveReference(ref)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	return resolved.String()
}

// urlToPath extracts the URL path component relative to the base host.
func urlToPath(jsURL, hostURL string) string {
	base := baseURL(hostURL)
	if strings.HasPrefix(jsURL, base) {
		p := jsURL[len(base):]
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		return p
	}
	u, err := url.Parse(jsURL)
	if err != nil {
		return jsURL
	}
	return u.Path
}

func classifySource(_ string, defaultSrc string) string {
	return defaultSrc
}

// ─── Misc helpers ──────────────────────────────────────────────────────────────

func extractTitle(body []byte) string {
	m := reTitleTag.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

func dedup(urls []string) []string {
	seen := make(map[string]struct{}, len(urls))
	out := urls[:0]
	for _, u := range urls {
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			out = append(out, u)
		}
	}
	return out
}

func countSecrets(files []JSFile) int {
	n := 0
	for _, f := range files {
		n += len(f.Secrets)
	}
	return n
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func writeHostResult(res HostResult, outputDir string) {
	// sanitize hostname for filename
	name := extractDomain(res.URL)
	if name == "" {
		name = "unknown"
	}
	name = strings.ReplaceAll(name, ":", "_")
	outPath := filepath.Join(outputDir, "js_"+name+".json")

	f, err := os.Create(outPath)
	if err != nil {
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	_ = enc.Encode(res)
}

// ─── Pre-compiled regular expressions ────────────────────────────────────────

var (
	// <script src="..."> or <script src='...'>
	reScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

	// Inline <script>...</script>
	reScriptInline = regexp.MustCompile(`(?is)<script(?:[^>]*(?:type=["'](?:text/javascript|module|application/javascript)["'])?[^>]*)?>([^<]{20,})</script>`)

	// String literals that look like JS file paths: "/path/to/file.js"
	reJSPathStr = regexp.MustCompile(`["'` + "`" + `]((?:[./][^\s"'` + "`" + `]*\.(?:js|jsx|mjs|ts|tsx))(?:\?[^"'` + "`" + `]*)?)["'` + "`" + `]`)

	// API endpoint paths in string literals: "/api/...", "/v1/...", "/graphql", etc.
	reAPIPath = regexp.MustCompile(`["'` + "`" + `](/(?:api|v\d+|graphql|rest|service|endpoint|internal|external|admin|auth|user|account|search|data|query|mutation|upload|download|webhook|ws|socket)[^"'` + "`" + `\s]{1,})["'` + "`" + `]`)

	// API endpoint paths inside fetch/axios/XHR calls
	reAPICall = regexp.MustCompile(`(?:fetch|axios\.\w+|this\.\$(?:http|axios)\.\w+|Vue\.http\.\w+|http\.(?:get|post|put|delete|patch|request))\s*\(\s*["'` + "`" + `](/[a-zA-Z0-9/_\-\.?&=%#@:]{2,})["'` + "`" + `]`)

	// Source map comment in JS
	reSourceMapComment = regexp.MustCompile(`(?m)//# sourceMappingURL=`)

	// <title>...</title>
	reTitleTag = regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,300})</title>`)

	// Version path segment: /v1/, /v2/, etc.
	reVersionPath = regexp.MustCompile(`/v\d+/`)
)
