package Core

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	wapp "github.com/projectdiscovery/wappalyzergo"
)

const (
	RED   = "\033[31m"
	GREEN = "\033[32m"
	RESET = "\033[0m"
)

// TechInfo содержит информацию об обнаруженной технологии.
type TechInfo struct {
	Categories []string `json:"categories,omitempty"`
	Version    string   `json:"version,omitempty"`
	Website    string   `json:"website,omitempty"`
}

// Result — данные по одному хосту.
type Result struct {
	URL          string              `json:"url"`
	Timestamp    string              `json:"timestamp"`
	StatusCode   int                 `json:"status_code,omitempty"`
	Title        string              `json:"title,omitempty"`
	Server       string              `json:"server,omitempty"`
	PoweredBy    string              `json:"x_powered_by,omitempty"`
	Error        string              `json:"error,omitempty"`
	Technologies map[string]TechInfo `json:"technologies,omitempty"`
}

func newHttpClient(timeout time.Duration, proxyURL string) *http.Client {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   8 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err == nil {
			tr.Proxy = http.ProxyURL(u)
		} else {
			log.Printf(RED+"[WARN]"+RESET+" bad proxy URL %s: %v\n", proxyURL, err)
		}
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// WappalyzerScan делает HTTP GET, собирает технологии, заголовки, title.
func WappalyzerScan(ctx context.Context, client *http.Client, target string) (Result, error) {
	result := Result{URL: target}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Интересные заголовки
	result.Server = resp.Header.Get("Server")
	result.PoweredBy = resp.Header.Get("X-Powered-By")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB лимит
	if err != nil {
		return result, err
	}

	// Извлечь title страницы
	result.Title = extractTitle(body)

	// Wappalyzer fingerprint с категориями
	wc, err := wapp.New()
	if err != nil {
		return result, fmt.Errorf("wappalyzer init: %v", err)
	}

	appInfoMap := wc.FingerprintWithInfo(resp.Header, body)

	// Дополняем версиями из заголовков
	headerVersions := extractVersionsFromHeaders(resp.Header, result.Server, result.PoweredBy)

	result.Technologies = make(map[string]TechInfo, len(appInfoMap))
	for name, info := range appInfoMap {
		ti := TechInfo{
			Categories: info.Categories,
			Website:    info.Website,
		}
		// Если в заголовках нашли версию для этой технологии — добавляем
		if v, ok := headerVersions[strings.ToLower(name)]; ok {
			ti.Version = v
		}
		result.Technologies[name] = ti
	}

	// Добавляем технологии из заголовков, которые wappalyzer мог пропустить
	for techName, version := range headerVersions {
		normalized := normalizeTechName(techName)
		if _, exists := result.Technologies[normalized]; !exists {
			result.Technologies[normalized] = TechInfo{Version: version}
		}
	}

	return result, nil
}

// extractTitle вытаскивает содержимое тега <title>.
func extractTitle(body []byte) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,200})</title>`)
	m := re.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// extractVersionsFromHeaders парсит версии из типичных HTTP-заголовков.
func extractVersionsFromHeaders(headers http.Header, server, poweredBy string) map[string]string {
	result := make(map[string]string)

	// Server: nginx/1.18.0, Apache/2.4.41 (Ubuntu), openresty/1.19.3.1
	if server != "" {
		if v := parseVersion(server); v.name != "" {
			result[strings.ToLower(v.name)] = v.version
		}
	}

	// X-Powered-By: PHP/8.1.2, Express, ASP.NET
	if poweredBy != "" {
		if v := parseVersion(poweredBy); v.name != "" {
			result[strings.ToLower(v.name)] = v.version
		}
	}

	// X-AspNet-Version: 4.0.30319
	if v := headers.Get("X-AspNet-Version"); v != "" {
		result["asp.net"] = v
	}

	// X-Generator: WordPress 6.4.2
	if gen := headers.Get("X-Generator"); gen != "" {
		if v := parseVersion(gen); v.name != "" {
			result[strings.ToLower(v.name)] = v.version
		}
	}

	// X-Drupal-Cache, X-WordPress-... etc
	for _, h := range []string{"X-Drupal-Cache", "X-Drupal-Dynamic-Cache"} {
		if headers.Get(h) != "" {
			result["drupal"] = ""
		}
	}

	return result
}

type nameVersion struct{ name, version string }

// parseVersion разбирает строки типа "nginx/1.18.0", "PHP/8.1.2", "WordPress 6.4".
func parseVersion(s string) nameVersion {
	// "Name/Version" формат
	re1 := regexp.MustCompile(`^([A-Za-z][A-Za-z0-9._-]+)/(\S+)`)
	if m := re1.FindStringSubmatch(s); len(m) == 3 {
		return nameVersion{m[1], m[2]}
	}
	// "Name Version" формат
	re2 := regexp.MustCompile(`^([A-Za-z][A-Za-z0-9._-]+)\s+(\d[\d.]+)`)
	if m := re2.FindStringSubmatch(s); len(m) == 3 {
		return nameVersion{m[1], m[2]}
	}
	return nameVersion{}
}

// normalizeTechName капитализирует известные названия.
func normalizeTechName(s string) string {
	known := map[string]string{
		"nginx": "Nginx", "apache": "Apache", "php": "PHP",
		"wordpress": "WordPress", "drupal": "Drupal", "asp.net": "ASP.NET",
		"express": "Express", "openresty": "OpenResty",
	}
	if v, ok := known[strings.ToLower(s)]; ok {
		return v
	}
	if len(s) > 0 {
		return strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

func WappalyzerMain(input, output string) {
	workers := runtime.NumCPU() * 2
	timeout := 15 * time.Second
	proxyEnv := os.Getenv("PROXY")

	f, err := os.Open(input)
	if err != nil {
		log.Fatalf(RED+"[FATAL]"+RESET+" can't open %s: %v\n", input, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var targets []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			line = "https://" + line
		}
		targets = append(targets, line)
	}

	client := newHttpClient(timeout, proxyEnv)

	jobs := make(chan string, len(targets))
	results := make(chan Result, len(targets))
	var wg sync.WaitGroup

	ctxRoot := context.Background()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				start := time.Now().UTC()
				ctx, cancel := context.WithTimeout(ctxRoot, timeout+5*time.Second)
				res, err := WappalyzerScan(ctx, client, t)
				cancel()

				res.Timestamp = start.Format(time.RFC3339)
				if err != nil {
					res.Error = err.Error()
					log.Printf(RED+"[ERR]"+RESET+" %s → %s\n", t, err)
				} else {
					log.Printf("[OK] %s → %d технологий\n", t, len(res.Technologies))
				}
				results <- res
			}
		}()
	}

	for _, t := range targets {
		jobs <- t
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var out []Result
	for r := range results {
		out = append(out, r)
	}

	of, err := os.Create(output)
	if err != nil {
		log.Fatalf(RED+"[FATAL]"+RESET+" can't create %s: %v\n", output, err)
	}
	defer of.Close()

	enc := json.NewEncoder(of)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		log.Fatalf(RED+"[FATAL]"+RESET+" can't write json: %v\n", err)
	}

	log.Printf("Wappalyzer done → %s\n", output)
}
