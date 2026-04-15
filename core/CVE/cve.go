// Package cveanalyzer performs async CVE lookups for every technology detected
// by Wappalyzer. It queries the NVD API 2.0, deduplicates by (tech, version),
// rate-limits to stay within NVD free-tier limits, and writes a per-host JSON
// report that the HTML report builder reads.
//
// Rate limits:
//   - Without API key (default): 5 req / 30s  → 1 req every 7s
//   - With NVD_API_KEY env var: 50 req / 30s  → 1 req every 700ms
//
// Set NVD_API_KEY in .env for faster scanning.
package cveanalyzer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	Core "Astarot/core/Analyze"
)

// ─── Entry point ──────────────────────────────────────────────────────────────

// CVEMain reads Wappalyzer results from wappalyzerFile, queries NVD for every
// unique (technology, version) pair, and writes tmp/cve_results.json.
// proxyURLs is forwarded to the HTTP client (same proxy list as other modules).
func CVEMain(wappalyzerFile string, proxyURLs []string, outputDir string) {
	wappResults, err := loadWappalyzer(wappalyzerFile)
	if err != nil {
		fmt.Printf("  \033[91m[CVE]\033[0m  Cannot read %s: %v\n", wappalyzerFile, err)
		return
	}
	if len(wappResults) == 0 {
		fmt.Printf("  \033[93m[CVE]\033[0m  No Wappalyzer results — skipping CVE scan.\n")
		return
	}

	client := buildHTTPClient(proxyURLs, 20*time.Second)

	// Rate limiter: 1 token per interval
	interval := 7 * time.Second
	if key := os.Getenv("NVD_API_KEY"); key != "" {
		interval = 700 * time.Millisecond
		fmt.Printf("  \033[90m→\033[0m  NVD_API_KEY detected — fast mode (%v/req)\n", interval)
	}
	rateLimiter := time.NewTicker(interval)
	defer rateLimiter.Stop()

	// ── Step 1: collect unique (tech, version) pairs ──────────────────────────
	type techKey struct{ name, version string }
	techIndex := make(map[techKey]struct{})
	// hostIndex maps (hostURL → []techKey)
	hostIndex := make(map[string][]techKey)

	for _, r := range wappResults {
		for rawName, info := range r.Technologies {
			name, version := parseTechName(rawName, info.Version)
			if !shouldQuery(name, info.Categories) {
				continue
			}
			tk := techKey{name, version}
			techIndex[tk] = struct{}{}
			hostIndex[r.URL] = append(hostIndex[r.URL], tk)
		}
	}

	fmt.Printf("  \033[90m→\033[0m  CVE scan: \033[97m%d\033[0m unique (tech, version) pairs\n", len(techIndex))

	// ── Step 2: query NVD for each unique pair ────────────────────────────────
	cveCache := make(map[techKey]TechCVE)
	var cacheMu sync.Mutex

	total := len(techIndex)
	done := 0

	for tk := range techIndex {
		<-rateLimiter.C // wait for rate-limit token

		done++
		searchTerm := resolveSearchTerm(tk.name, tk.version)
		fmt.Printf("  \033[90m[CVE %d/%d]\033[0m  %s%s\033[0m  →  ",
			done, total,
			"\033[97m", searchTerm,
		)

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		tc, err := queryNVD(ctx, client, searchTerm, tk.name, tk.version)
		cancel()

		if err != nil {
			fmt.Printf("\033[91merr: %v\033[0m\n", err)
		} else {
			color := "\033[90m"
			if countBySeverity(tc.CVEs, "CRITICAL") > 0 {
				color = "\033[91m"
			} else if countBySeverity(tc.CVEs, "HIGH") > 0 {
				color = "\033[93m"
			} else if len(tc.CVEs) > 0 {
				color = "\033[97m"
			}
			fmt.Printf("%s%d CVE(s)\033[0m\n", color, len(tc.CVEs))
		}

		cacheMu.Lock()
		cveCache[tk] = tc
		cacheMu.Unlock()
	}

	// ── Step 3: assemble per-host results ─────────────────────────────────────
	var hostResults []HostCVEResult
	for _, r := range wappResults {
		tks := hostIndex[r.URL]
		if len(tks) == 0 {
			continue
		}
		hr := HostCVEResult{HostURL: r.URL}
		cacheMu.Lock()
		for _, tk := range tks {
			if tc, ok := cveCache[tk]; ok && (len(tc.CVEs) > 0 || tc.Error != "") {
				hr.Findings = append(hr.Findings, tc)
			}
		}
		cacheMu.Unlock()
		// Sort findings: most CVEs first
		sort.Slice(hr.Findings, func(i, j int) bool {
			return len(hr.Findings[i].CVEs) > len(hr.Findings[j].CVEs)
		})
		if len(hr.Findings) > 0 {
			hostResults = append(hostResults, hr)
		}
	}

	// ── Step 4: write output ──────────────────────────────────────────────────
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("  \033[91m[CVE]\033[0m  Cannot create output dir: %v\n", err)
		return
	}

	report := CVEReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Hosts:     hostResults,
	}

	outPath := filepath.Join(outputDir, "cve_results.json")
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Printf("  \033[91m[CVE]\033[0m  Cannot create output file: %v\n", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)

	// Summary
	totalCVEs := 0
	critical := 0
	high := 0
	for _, hr := range hostResults {
		for _, tc := range hr.Findings {
			totalCVEs += len(tc.CVEs)
			critical += countBySeverity(tc.CVEs, "CRITICAL")
			high += countBySeverity(tc.CVEs, "HIGH")
		}
	}
	fmt.Printf("\n  \033[92m[CVE]\033[0m  Total: \033[97m%d\033[0m CVEs  \033[91mCritical: %d\033[0m  \033[93mHigh: %d\033[0m  →  \033[92m\033[1m%s\033[0m\n",
		totalCVEs, critical, high, outPath)
}

// ─── NVD API 2.0 query ────────────────────────────────────────────────────────

func queryNVD(ctx context.Context, client *http.Client, searchTerm, techName, version string) (TechCVE, error) {
	tc := TechCVE{
		Technology: techName,
		Version:    version,
		SearchTerm: searchTerm,
	}

	params := url.Values{}
	params.Set("keywordSearch", searchTerm)
	params.Set("resultsPerPage", "15")

	apiURL := "https://services.nvd.nist.gov/rest/json/cves/2.0?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		tc.Error = err.Error()
		return tc, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; security-scanner/1.0)")
	req.Header.Set("Accept", "application/json")
	if key := os.Getenv("NVD_API_KEY"); key != "" {
		req.Header.Set("apiKey", key)
	}

	resp, err := client.Do(req)
	if err != nil {
		tc.Error = err.Error()
		return tc, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		tc.Error = "NVD rate limited (403) — set NVD_API_KEY or slow down"
		return tc, fmt.Errorf("NVD 403")
	}
	if resp.StatusCode != 200 {
		tc.Error = fmt.Sprintf("NVD HTTP %d", resp.StatusCode)
		return tc, fmt.Errorf("NVD HTTP %d", resp.StatusCode)
	}

	var nvdResp nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		tc.Error = err.Error()
		return tc, err
	}

	for _, vuln := range nvdResp.Vulnerabilities {
		entry := parseCVEEntry(vuln.CVE)
		// Filter: skip entries with no CVSS score
		if entry.CVSSScore == 0 {
			continue
		}
		tc.CVEs = append(tc.CVEs, entry)
	}

	// Sort by CVSS score descending
	sort.Slice(tc.CVEs, func(i, j int) bool {
		return tc.CVEs[i].CVSSScore > tc.CVEs[j].CVSSScore
	})

	// Keep top 10 per tech to avoid bloat
	if len(tc.CVEs) > 10 {
		tc.CVEs = tc.CVEs[:10]
	}

	return tc, nil
}

func parseCVEEntry(cve nvdCVE) CVEEntry {
	entry := CVEEntry{
		ID:        cve.ID,
		Published: strings.SplitN(cve.Published, "T", 2)[0],
		NVDURL:    "https://nvd.nist.gov/vuln/detail/" + cve.ID,
	}

	// English description
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			desc := d.Value
			if len(desc) > 200 {
				desc = desc[:200] + "…"
			}
			entry.Description = desc
			break
		}
	}

	// CVSS score: prefer v3.1 > v3.0 > v2
	switch {
	case len(cve.Metrics.V31) > 0:
		entry.CVSSScore = cve.Metrics.V31[0].CVSSData.BaseScore
		entry.Severity = cve.Metrics.V31[0].CVSSData.BaseSeverity
	case len(cve.Metrics.V30) > 0:
		entry.CVSSScore = cve.Metrics.V30[0].CVSSData.BaseScore
		entry.Severity = cve.Metrics.V30[0].CVSSData.BaseSeverity
	case len(cve.Metrics.V2) > 0:
		entry.CVSSScore = cve.Metrics.V2[0].CVSSData.BaseScore
		entry.Severity = cve.Metrics.V2[0].BaseSeverity
	}

	return entry
}

// ─── Tech name helpers ────────────────────────────────────────────────────────

// parseTechName handles both "Nginx:1.24.0" and {"version":"1.24.0"} formats
// from Wappalyzer output.
func parseTechName(rawName, infoVersion string) (name, version string) {
	// "Nginx:1.24.0" format
	if idx := strings.Index(rawName, ":"); idx > 0 {
		name = rawName[:idx]
		version = rawName[idx+1:]
		return
	}
	name = rawName
	version = infoVersion
	return
}

// shouldQuery returns true if the technology is worth a CVE lookup.
func shouldQuery(name string, categories []string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	// Skip if ALL categories are in the skip list
	if len(categories) > 0 {
		skip := true
		for _, cat := range categories {
			if !skipCategories[cat] {
				skip = false
				break
			}
		}
		if skip {
			return false
		}
	}
	return true
}

// resolveSearchTerm builds the NVD keyword search string for a technology.
func resolveSearchTerm(name, version string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	term := lower
	if mapped, ok := techSearchMap[lower]; ok {
		term = mapped
	}
	if version != "" {
		term = term + " " + version
	}
	return term
}

// ─── HTTP client ──────────────────────────────────────────────────────────────

func buildHTTPClient(proxyURLs []string, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: false,
	}

	// Use first working proxy if provided
	for _, pu := range proxyURLs {
		u, err := url.Parse(pu)
		if err != nil {
			continue
		}
		if strings.HasPrefix(pu, "http://") || strings.HasPrefix(pu, "https://") {
			tr.Proxy = http.ProxyURL(u)
			break
		}
		// socks5 — skip for simplicity (NVD is public, direct is fine)
	}

	return &http.Client{Transport: tr, Timeout: timeout}
}

// ─── Wappalyzer loader ────────────────────────────────────────────────────────

func loadWappalyzer(path string) ([]Core.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var results []Core.Result
	return results, json.Unmarshal(data, &results)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func countBySeverity(cves []CVEEntry, severity string) int {
	n := 0
	for _, c := range cves {
		if strings.EqualFold(c.Severity, severity) {
			n++
		}
	}
	return n
}
