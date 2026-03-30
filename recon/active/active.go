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
	"time"

	"golang.org/x/net/proxy"

	"Astarot/core"
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

// PrepareProxies загружает и валидирует прокси, при необходимости задаёт вопрос пользователю.
// Вызывать ДО запуска горутин, чтобы CLI-вопрос не перебивался параллельным выводом.
// Возвращает (валидные прокси, запускать ли брутфорс).
func PrepareProxies() ([]*ProxyInfo, bool) {
	rawProxies, _ := loadProxies("proxies.txt")
	validProxies := validateProxies(rawProxies)

	if len(validProxies) == 0 {
		fmt.Print("\n[?] Рабочие прокси не найдены. Запустить брутфорс без прокси? (y/n): ")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			return nil, false
		}
		return nil, true // брутфорс без прокси
	}

	fmt.Printf("[✓] Рабочих прокси: %d\n", len(validProxies))
	return validProxies, true
}

// Active выполняет активный брутфорс субдоменов с заранее подготовленными прокси.
// proxies и runBrute получаются из PrepareProxies() — до запуска горутин.
func Active(domain string, workersCount int, w *core.SafeWriter, proxies []*ProxyInfo, runBrute bool) error {
	if !runBrute {
		fmt.Println("[!] Активный брутфорс пропущен.")
		return nil
	}

	var pool *ProxyPool
	if len(proxies) > 0 {
		pool = newPool(proxies, 0) // maxRequests вычислится после загрузки субдоменов
	} else {
		fmt.Println("[*] Запуск без прокси...")
	}

	// 3. Загрузить субдомены
	subdomains, err := loadSubdomains("subList.txt")
	if err != nil {
		return fmt.Errorf("ошибка загрузки субдоменов: %v", err)
	}
	if len(subdomains) == 0 {
		return fmt.Errorf("субдомены не найдены в subList.txt")
	}
	fmt.Printf("[*] Субдоменов для брутфорса: %d\n", len(subdomains))

	// Настроить распределение запросов по прокси
	if pool != nil {
		pool.maxRequests = len(subdomains) / len(proxies)
		if pool.maxRequests < 1 {
			pool.maxRequests = 1
		}
	}

	// 4. Запустить воркеры
	subChan := make(chan string, len(subdomains))
	for _, sub := range subdomains {
		subChan <- sub
	}
	close(subChan)

	var wg sync.WaitGroup
	for i := 0; i < workersCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			worker(id, domain, subChan, w, pool)
		}(i)
	}

	wg.Wait()
	fmt.Println("\n[✓] Активный брутфорс завершён!")
	return nil
}

// validateProxies проверяет каждую прокси параллельно и возвращает только рабочие.
func validateProxies(proxies []*ProxyInfo) []*ProxyInfo {
	if len(proxies) == 0 {
		return nil
	}

	fmt.Printf("[*] Проверка %d прокси...\n", len(proxies))

	var mu sync.Mutex
	var valid []*ProxyInfo
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20) // максимум 20 одновременных проверок

	for _, p := range proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(pi *ProxyInfo) {
			defer wg.Done()
			defer func() { <-sem }()
			if isProxyAlive(pi) {
				mu.Lock()
				valid = append(valid, pi)
				mu.Unlock()
			}
		}(p)
	}

	wg.Wait()
	fmt.Printf("[✓] Рабочих прокси: %d из %d\n", len(valid), len(proxies))
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

// worker обрабатывает субдомены из канала.
func worker(id int, domain string, subChan <-chan string, w *core.SafeWriter, pool *ProxyPool) {
	for subdomain := range subChan {
		fullDomain := subdomain + "." + domain

		var proxyInfo *ProxyInfo
		if pool != nil {
			proxyInfo = pool.getNextProxy()
		}

		if isAlive(fullDomain, proxyInfo) {
			_ = w.WriteLine(fullDomain)
			proxyLabel := "без прокси"
			if proxyInfo != nil {
				proxyLabel = maskProxy(proxyInfo.URL)
			}
			fmt.Printf("[Worker %d] [✓] %s (%s)\n", id, fullDomain, proxyLabel)
		}
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
