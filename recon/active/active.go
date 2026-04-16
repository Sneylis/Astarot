package active

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/Sneylis/Astarot/core"
)

// proxyCheckURL используется для валидации прокси — доступный, надёжный хост.
const proxyCheckURL = "http://example.com"

// ProxyInfo хранит данные об одной прокси.
type ProxyInfo struct {
	URL       string
	ProxyType string // "socks5" or "http"
}

// ProxyPool управляет ротацией прокси.
type ProxyPool struct {
	proxies      []*ProxyInfo
	mu           sync.Mutex
	currentIndex int
	reqCount     int
	maxRequests  int // запросов на одну прокси перед ротацией
}

// PrepareProxies загружает и валидирует прокси из указанного файла, при необходимости
// задаёт вопрос пользователю. Вызывать ДО запуска горутин.
// Возвращает (валидные прокси, запускать ли брутфорс).
func PrepareProxies(proxiesFile string) ([]*ProxyInfo, bool) {
	if proxiesFile == "" {
		proxiesFile = "proxies.txt"
	}
	rawProxies, err := loadProxies(proxiesFile)
	if err != nil {
		fmt.Printf("  \033[91m[✗]\033[0m  Cannot read proxy file %q: %v\n", proxiesFile, err)
	} else if len(rawProxies) == 0 {
		fmt.Printf("  \033[93m[!]\033[0m  Proxy file %q is empty or not found.\n", proxiesFile)
	} else {
		fmt.Printf("  \033[90m→\033[0m  Loaded \033[97m%d\033[0m proxies from \033[96m%s\033[0m\n", len(rawProxies), proxiesFile)
	}

	validProxies := validateProxies(rawProxies)

	if len(validProxies) == 0 {
		fmt.Print("\n  \033[93m[?]\033[0m  No working proxies found. Run bruteforce without proxy? (y/n): ")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			return nil, false
		}
		return nil, true // брутфорс без прокси
	}

	fmt.Printf("\n  \033[92m[✔]\033[0m  Working proxies: \033[92m\033[1m%d\033[0m / %d\n",
		len(validProxies), len(rawProxies))
	return validProxies, true
}

// ─── Progress bar ────────────────────────────────────────────────────────────

// bruteProgress tracks brute-force progress and owns all terminal output
// during the scan so workers never interleave their lines.
type bruteProgress struct {
	total int
	barW  int
	done  atomic.Int64
	found atomic.Int64
	mu    sync.Mutex // guards all fmt.Print calls
}

func newBruteProgress(total int) *bruteProgress {
	return &bruteProgress{total: total, barW: 28}
}

// render builds the progress bar string (no newline, starts with \r).
func (bp *bruteProgress) render() string {
	d := int(bp.done.Load())
	f := int(bp.found.Load())
	pct := 0
	if bp.total > 0 {
		pct = d * 100 / bp.total
	}
	filled := pct * bp.barW / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", bp.barW-filled)
	return fmt.Sprintf(
		"\r  \033[90m→\033[0m  \033[96m[%s]\033[0m  \033[97m%3d%%\033[0m  \033[90m(%d/%d)\033[0m  \033[92m✔ %d found\033[0m   ",
		bar, pct, d, bp.total, f,
	)
}

// tick redraws the bar in place (called by ticker goroutine).
func (bp *bruteProgress) tick() {
	bp.mu.Lock()
	fmt.Print(bp.render())
	bp.mu.Unlock()
}

// inc marks one subdomain as processed and redraws the bar.
func (bp *bruteProgress) inc() {
	bp.done.Add(1)
}

// hit records a found subdomain: clears bar, prints the hit, redraws bar.
func (bp *bruteProgress) hit(domain string) {
	bp.found.Add(1)
	bp.mu.Lock()
	// \r\033[K — go to line start, erase to end
	fmt.Printf("\r\033[K  \033[92m[+]\033[0m  \033[97m%s\033[0m\n", domain)
	fmt.Print(bp.render())
	bp.mu.Unlock()
}

// finish prints the final state and moves to a new line.
func (bp *bruteProgress) finish() {
	bp.mu.Lock()
	fmt.Print(bp.render())
	fmt.Println()
	bp.mu.Unlock()
}

// ─── Active bruteforce ────────────────────────────────────────────────────────

// Active выполняет активный брутфорс субдоменов с заранее подготовленными прокси.
// proxies и runBrute получаются из PrepareProxies() — до запуска горутин.
// wordlistPath — путь к файлу со словарём субдоменов (передаётся флагом --Wsub).
func Active(domain string, workersCount int, w *core.SafeWriter, proxies []*ProxyInfo, runBrute bool, wordlistPath string) error {
	if !runBrute {
		fmt.Printf("  \033[93m[!]\033[0m  Active bruteforce skipped.\n")
		return nil
	}

	var pool *ProxyPool
	if len(proxies) > 0 {
		pool = newPool(proxies, 0)
	}

	if wordlistPath == "" {
		wordlistPath = "subList.txt"
	}
	subdomains, err := loadSubdomains(wordlistPath)
	if err != nil {
		return fmt.Errorf("load wordlist: %v", err)
	}
	if len(subdomains) == 0 {
		return fmt.Errorf("wordlist %q is empty", wordlistPath)
	}

	if pool != nil {
		pool.maxRequests = len(subdomains) / len(proxies)
		if pool.maxRequests < 1 {
			pool.maxRequests = 1
		}
	}

	proxyLabel := "direct"
	if pool != nil {
		proxyLabel = fmt.Sprintf("%d proxies", len(proxies))
	}
	fmt.Printf("  \033[90m→\033[0m  Wordlist: \033[97m%d\033[0m entries  ·  workers: \033[97m%d\033[0m  ·  %s\n",
		len(subdomains), workersCount, proxyLabel)

	bp := newBruteProgress(len(subdomains))

	// Ticker redraws progress bar every 150ms
	stopTicker := make(chan struct{})
	go func() {
		t := time.NewTicker(150 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				bp.tick()
			case <-stopTicker:
				return
			}
		}
	}()

	subChan := make(chan string, len(subdomains))
	for _, sub := range subdomains {
		subChan <- sub
	}
	close(subChan)

	var wg sync.WaitGroup
	for range workersCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(domain, subChan, w, pool, bp)
		}()
	}

	wg.Wait()
	close(stopTicker)
	bp.finish()
	return nil
}

// validateProxies проверяет каждую прокси параллельно.
// Сначала выводит весь список (мгновенно), затем результаты появляются по мере ответов.
func validateProxies(proxies []*ProxyInfo) []*ProxyInfo {
	if len(proxies) == 0 {
		return nil
	}

	// ── Немедленно показываем что будем проверять ─────────────────────────────
	fmt.Printf("  \033[90m→\033[0m  Found \033[97m%d\033[0m proxies to validate:\n\n", len(proxies))
	for i, p := range proxies {
		fmt.Printf("      \033[90m%2d.\033[0m  \033[90m%s\033[0m\n", i+1, maskProxy(p.URL))
	}
	fmt.Printf("\n  \033[90m→\033[0m  Checking in parallel…\n\n")

	// ── Параллельная проверка, результаты выводятся по мере поступления ───────
	var mu sync.Mutex
	var valid []*ProxyInfo
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)

	for _, p := range proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(pi *ProxyInfo) {
			defer wg.Done()
			defer func() { <-sem }()

			start := time.Now()
			alive := isProxyAlive(pi)
			elapsed := time.Since(start).Milliseconds()
			label := maskProxy(pi.URL)

			mu.Lock()
			defer mu.Unlock()
			if alive {
				valid = append(valid, pi)
				fmt.Printf("      \033[92m[✔]\033[0m  \033[97m%-52s\033[0m  \033[92malive\033[0m  \033[90m%dms\033[0m\n", label, elapsed)
			} else {
				fmt.Printf("      \033[91m[✗]\033[0m  \033[90m%-52s\033[0m  \033[91mdead\033[0m   \033[90m%dms\033[0m\n", label, elapsed)
			}
		}(p)
	}

	wg.Wait()
	fmt.Println()
	return valid
}

// isProxyAlive делает тестовый запрос через прокси.
func isProxyAlive(pi *ProxyInfo) bool {
	client, err := createHTTPClient(pi, 5*time.Second)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", proxyCheckURL, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// newPool создаёт ProxyPool из провалидированных прокси.
func newPool(proxies []*ProxyInfo, maxRequests int) *ProxyPool {
	return &ProxyPool{
		proxies:     proxies,
		maxRequests: maxRequests,
	}
}

// getNextProxy возвращает следующую прокси с ротацией.
func (p *ProxyPool) getNextProxy() *ProxyInfo {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.reqCount++
	if p.reqCount >= p.maxRequests {
		p.reqCount = 0
		p.currentIndex = (p.currentIndex + 1) % len(p.proxies)
	}

	return p.proxies[p.currentIndex]
}

// worker обрабатывает субдомены из канала, обновляя прогресс-бар.
func worker(domain string, subChan <-chan string, w *core.SafeWriter, pool *ProxyPool, bp *bruteProgress) {
	for subdomain := range subChan {
		fullDomain := subdomain + "." + domain

		var proxyInfo *ProxyInfo
		if pool != nil {
			proxyInfo = pool.getNextProxy()
		}

		if isAlive(fullDomain, proxyInfo) {
			_ = w.WriteLine(fullDomain)
			bp.hit(fullDomain)
		}
		bp.inc()
	}
}

// isAlive проверяет хост через HTTPS, затем HTTP. Принимает коды 200-399.
func isAlive(host string, proxyInfo *ProxyInfo) bool {
	for _, scheme := range []string{"https://", "http://"} {
		targetURL := scheme + host

		var (
			client *http.Client
			err    error
		)
		if proxyInfo != nil {
			client, err = createHTTPClient(proxyInfo, 10*time.Second)
		} else {
			client = createDirectHTTPClient(10 * time.Second)
		}
		if err != nil {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, reqErr := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if reqErr != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, doErr := client.Do(req)
		cancel()
		if doErr != nil {
			continue
		}
		resp.Body.Close()

		// Только успешные и редиректные коды считаются живыми
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return true
		}
	}
	return false
}

// createHTTPClient создаёт HTTP клиент с заданной прокси.
func createHTTPClient(proxyInfo *ProxyInfo, timeout time.Duration) (*http.Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	switch proxyInfo.ProxyType {
	case "socks5":
		proxyURL, err := url.Parse(proxyInfo.URL)
		if err != nil {
			return nil, err
		}
		var auth *proxy.Auth
		if proxyURL.User != nil {
			password, _ := proxyURL.User.Password()
			auth = &proxy.Auth{
				User:     proxyURL.User.Username(),
				Password: password,
			}
		}
		dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}

	case "http":
		proxyURL, err := url.Parse(proxyInfo.URL)
		if err != nil {
			return nil, err
		}
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// createDirectHTTPClient создаёт HTTP клиент без прокси.
func createDirectHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// loadProxies читает прокси из файла. Если файл не существует — возвращает nil без ошибки.
func loadProxies(filename string) ([]*ProxyInfo, error) {
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var proxies []*ProxyInfo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var proxyType string
		switch {
		case strings.HasPrefix(line, "socks5://"):
			proxyType = "socks5"
		case strings.HasPrefix(line, "http://"):
			proxyType = "http"
		default:
			continue
		}
		proxies = append(proxies, &ProxyInfo{URL: line, ProxyType: proxyType})
	}
	return proxies, scanner.Err()
}

// loadSubdomains читает список субдоменов из файла (по одному на строку).
func loadSubdomains(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			subs = append(subs, line)
		}
	}
	return subs, scanner.Err()
}

// maskProxy скрывает пароль в URL прокси для вывода в лог.
func maskProxy(proxyURL string) string {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return proxyURL
	}
	if u.User != nil {
		return fmt.Sprintf("%s://%s:***@%s", u.Scheme, u.User.Username(), u.Host)
	}
	return proxyURL
}
