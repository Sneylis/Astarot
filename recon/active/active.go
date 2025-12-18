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
)

type ProxyInfo struct {
	URL       string
	ProxyType string // "socks5" or "http"
	Used      int
	LastUsed  time.Time
}

type ProxyPool struct {
	proxies       []*ProxyInfo
	mu            sync.Mutex
	currentIndex  int
	requestsCount int
	maxRequests   int // 3-4 запроса на прокси
}

// Active выполняет активный перебор субдоменов через прокси
func Active(domain string, workersCount int) error {
	// Читаем прокси
	proxies, err := loadProxies("proxies.txt")
	if err != nil {
		return fmt.Errorf("ошибка загрузки прокси: %v", err)
	}

	if len(proxies) == 0 {
		return fmt.Errorf("не найдено прокси в файле proxies.txt")
	}

	// Читаем список субдоменов
	subdomains, err := loadSubdomains("subList.txt")
	if err != nil {
		return fmt.Errorf("ошибка загрузки субдоменов: %v", err)
	}

	if len(subdomains) == 0 {
		return fmt.Errorf("не найдено субдоменов в файле subList.txt")
	}

	// Создаем пул прокси с умной ротацией
	pool := &ProxyPool{
		proxies:      proxies,
		maxRequests:  3 + len(proxies)%2, // 3-4 запроса в зависимости от количества
		currentIndex: 0,
	}

	// Создаем tmp директорию если не существует
	if err := os.MkdirAll("tmp", 0755); err != nil {
		return fmt.Errorf("ошибка создания директории tmp: %v", err)
	}

	// Канал для субдоменов и результатов
	subChan := make(chan string, len(subdomains))
	resultsChan := make(chan string, 100)

	// Заполняем канал субдоменами
	for _, sub := range subdomains {
		subChan <- sub
	}
	close(subChan)

	// WaitGroup для воркеров
	var wg sync.WaitGroup

	// Запускаем воркеры
	for i := 0; i < workersCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			worker(workerID, domain, subChan, resultsChan, pool)
		}(i)
	}

	// Горутина для записи результатов
	doneChan := make(chan struct{})
	go writeResults(resultsChan, doneChan)

	// Ждем завершения всех воркеров
	wg.Wait()
	close(resultsChan)
	<-doneChan

	fmt.Println("\n[✓] Сканирование завершено!")
	return nil
}

// loadProxies читает прокси из файла
func loadProxies(filename string) ([]*ProxyInfo, error) {
	file, err := os.Open(filename)
	if err != nil {
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
		if strings.HasPrefix(line, "socks5://") {
			proxyType = "socks5"
		} else if strings.HasPrefix(line, "http://") {
			proxyType = "http"
		} else {
			continue
		}

		proxies = append(proxies, &ProxyInfo{
			URL:       line,
			ProxyType: proxyType,
			Used:      0,
			LastUsed:  time.Time{},
		})
	}

	return proxies, scanner.Err()
}

// loadSubdomains читает субдомены из файла
func loadSubdomains(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			subdomains = append(subdomains, line)
		}
	}

	return subdomains, scanner.Err()
}

// getNextProxy возвращает следующую прокси с умной ротацией
func (p *ProxyPool) getNextProxy() *ProxyInfo {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Увеличиваем счетчик запросов
	p.requestsCount++

	// Если достигли лимита запросов на текущую прокси
	if p.requestsCount >= p.maxRequests {
		p.requestsCount = 0
		p.currentIndex = (p.currentIndex + 1) % len(p.proxies)

		// Если прокси мало (2-3), минимальный перерыв
		// Если много (10+), даем отдохнуть больше
		if len(p.proxies) <= 3 {
			time.Sleep(100 * time.Millisecond)
		} else {
			// Вычисляем время отдыха пропорционально количеству прокси
			restTime := time.Duration(len(p.proxies)*50) * time.Millisecond
			time.Sleep(restTime)
		}
	}

	currentProxy := p.proxies[p.currentIndex]
	currentProxy.Used++
	currentProxy.LastUsed = time.Now()

	return currentProxy
}

// worker обрабатывает субдомены
func worker(id int, domain string, subChan <-chan string, resultsChan chan<- string, pool *ProxyPool) {
	for subdomain := range subChan {
		fullDomain := subdomain + "." + domain

		// Получаем прокси
		proxyInfo := pool.getNextProxy()

		// Проверяем хост
		if isAlive(fullDomain, proxyInfo) {
			resultsChan <- fullDomain
			fmt.Printf("[Worker %d] [✓] %s (proxy: %s)\n", id, fullDomain, maskProxy(proxyInfo.URL))
		}
	}
}

// isAlive проверяет, живой ли хост
func isAlive(host string, proxyInfo *ProxyInfo) bool {
	// Пробуем оба протокола
	protocols := []string{"https://", "http://"}

	for _, protocol := range protocols {
		targetURL := protocol + host

		client, err := createHTTPClient(proxyInfo, 10*time.Second)
		if err != nil {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Считаем живым, если получили ответ с кодом 200-499
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			return true
		}
	}

	return false
}

// createHTTPClient создает HTTP клиент с прокси
func createHTTPClient(proxyInfo *ProxyInfo, timeout time.Duration) (*http.Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	if proxyInfo.ProxyType == "socks5" {
		// Парсим SOCKS5 прокси
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

		tr.Dial = func(network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
	} else if proxyInfo.ProxyType == "http" {
		// HTTP прокси
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
			return http.ErrUseLastResponse // Не следуем редиректам
		},
	}, nil
}

// writeResults записывает живые домены в файл
func writeResults(resultsChan <-chan string, doneChan chan<- struct{}) {
	file, err := os.OpenFile("tmp/alive.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Ошибка создания файла результатов: %v\n", err)
		doneChan <- struct{}{}
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for domain := range resultsChan {
		_, err := writer.WriteString(domain + "\n")
		if err != nil {
			fmt.Printf("Ошибка записи в файл: %v\n", err)
		}
	}

	doneChan <- struct{}{}
}

// maskProxy маскирует прокси для вывода (скрывает пароль)
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
