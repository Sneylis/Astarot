package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
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

type AliveConfig struct {
	Concurrency      int           // число воркеров
	Timeout          time.Duration // общий таймаут запроса
	Retries          int           // ретраи на сетевые/5xx
	FollowRedirects  bool          // следовать редиректам
	HeadFirst        bool          // сначала HEAD, если 405/403 — фоллбэк на GET
	AcceptMin        int           // min HTTP код (включ.)
	AcceptMax        int           // max HTTP код (включ.)
	TryHTTPSThenHTTP bool          // если во входе хост, пробуем https:// и http://
	Paths            []string      // пути для проверки (обычно ["/"])
}

// разумные дефолты
func DefaultAliveConfig() AliveConfig {
	return AliveConfig{
		Concurrency:      80,
		Timeout:          7 * time.Second,
		Retries:          1,
		FollowRedirects:  true,
		HeadFirst:        true,
		AcceptMin:        200,
		AcceptMax:        399,
		TryHTTPSThenHTTP: true,
		Paths:            []string{"/"},
	}
}

// IS_allive читает raw.txt и proxies.txt, проверяет цели и пишет живые URL в out (который закрывает по завершению).
func IS_allive(ctx context.Context, rawFile, proxiesFile string, out chan<- string, cfg AliveConfig) error {
	defer close(out)

	// 1) загрузим цели
	targets, err := loadTargets(rawFile, cfg)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return nil
	}

	// 2) загрузим прокси (может быть пусто — тогда прямое соединение)
	proxies, err := loadProxies(proxiesFile)
	if err != nil {
		return err
	}

	// 3) подготовим пул воркеров
	jobs := make(chan string, 1024)
	var workersWG sync.WaitGroup

	// round-robin по прокси
	var clients []*http.Client
	if len(proxies) == 0 {
		clients = []*http.Client{buildClient(nil, cfg)}
	} else {
		for _, pu := range proxies {
			clients = append(clients, buildClient(pu, cfg))
		}
	}

	workerCount := cfg.Concurrency
	if workerCount <= 0 {
		workerCount = 20
	}

	for i := 0; i < workerCount; i++ {
		cli := clients[i%len(clients)]
		workersWG.Add(1)
		go func(client *http.Client) {
			defer workersWG.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case u, ok := <-jobs:
					if !ok {
						return
					}
					if checkOne(ctx, client, u, cfg) {
						select {
						case out <- u:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}(cli)
	}

	// 4) накидаем работы
	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	// 5) ждём воркеров
	workersWG.Wait()
	return nil
}

func loadTargets(path string, cfg AliveConfig) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open raw file: %w", err)
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var res []string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		// если это уже URL со схемой — берём как есть
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			u := normalizeURL(line)
			if u == "" {
				continue
			}
			if _, ok := seen[u]; !ok {
				seen[u] = struct{}{}
				res = append(res, u)
			}
			continue
		}

		// иначе это хост — расширяем до URL по cfg
		if cfg.TryHTTPSThenHTTP {
			for _, p := range cfg.Paths {
				if p == "" || !strings.HasPrefix(p, "/") {
					p = "/" + strings.TrimPrefix(p, "/")
				}
				for _, scheme := range []string{"https", "http"} {
					u := scheme + "://" + line + p
					u = normalizeURL(u)
					if u == "" {
						continue
					}
					if _, ok := seen[u]; !ok {
						seen[u] = struct{}{}
						res = append(res, u)
					}
				}
			}
		} else {
			u := "https://" + line
			u = normalizeURL(u)
			if u == "" {
				continue
			}
			if _, ok := seen[u]; !ok {
				seen[u] = struct{}{}
				res = append(res, u)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan raw file: %w", err)
	}
	return res, nil
}

func normalizeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	// уберём лишние пробелы, нормализуем путь
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String()
}

func loadProxies(path string) ([]*url.URL, error) {
	f, err := os.Open(path)
	if err != nil {
		// если файла нет — считаем, что работаем без прокси
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open proxies file: %w", err)
	}
	defer f.Close()

	var res []*url.URL
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		if u.Scheme == "" || u.Host == "" {
			continue
		}
		res = append(res, u)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan proxies: %w", err)
	}
	return res, nil
}

func buildClient(proxyURL *url.URL, cfg AliveConfig) *http.Client {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   cfg.Timeout / 2,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          200,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.Timeout / 2,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// HTTP(S) прокси
	if proxyURL != nil && (proxyURL.Scheme == "http" || proxyURL.Scheme == "https") {
		tr.Proxy = http.ProxyURL(proxyURL)
	}

	// SOCKS5 прокси (если нужен)
	if proxyURL != nil && strings.HasPrefix(proxyURL.Scheme, "socks5") {
		dialer, err := proxy.FromURL(proxyURL, &net.Dialer{
			Timeout:   cfg.Timeout / 2,
			KeepAlive: 30 * time.Second,
		})
		if err == nil {
			tr.Proxy = nil // не использовать HTTP Proxy
			// оборачиваем DialContext через socks5
			tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return dialer.Dial(network, address)
			}
		}
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
	}
	if !cfg.FollowRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

func checkOne(parent context.Context, client *http.Client, target string, cfg AliveConfig) bool {
	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()

	methods := []string{"GET"}
	if cfg.HeadFirst {
		methods = []string{"HEAD", "GET"}
	}

	var lastErr error
	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		for _, m := range methods {
			req, err := http.NewRequestWithContext(ctx, m, target, nil)
			if err != nil {
				lastErr = err
				continue
			}
			req.Header.Set("User-Agent", "Astarot-Probe/1.0")

			resp, err := client.Do(req)
			if err != nil {
				if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return false
				}
				lastErr = err
				continue
			}
			_ = resp.Body.Close()

			// фоллбек GET после "не любим" HEAD
			if m == "HEAD" && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusForbidden) {
				continue
			}

			if resp.StatusCode >= cfg.AcceptMin && resp.StatusCode <= cfg.AcceptMax {
				return true
			}
			// если редиректы не следуем — можно считать «живым» сам факт 3xx
			if !cfg.FollowRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
				return true
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		}

		// маленький бэкофф
		select {
		case <-time.After(time.Duration(200*(attempt+1)) * time.Millisecond):
		case <-ctx.Done():
			return false
		}
	}
	_ = lastErr
	return false
}
