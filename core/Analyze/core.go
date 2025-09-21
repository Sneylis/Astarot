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

func ClearDuplicate(input <-chan string) <-chan string {
	out := make(chan string)

	go func() {
		defer close(out)
		seen := make(map[string]bool)

		for item := range input {
			if !seen[item] {
				seen[item] = true
				out <- item
			}
		}
	}()
	return out
}

func SaveResults(ctx context.Context, in <-chan string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer func() {
		if err := writer.Flush(); err != nil {
			log.Println("[WARN] flush error:", err)
		}
	}()

	// Слушаем канал и сигнал контекста
	for {
		select {
		case domain, ok := <-in:
			if !ok {
				// канал закрыт, значит продюсеры закончили — нормальный выход
				return nil
			}
			if _, err := writer.WriteString(domain + "\n"); err != nil {
				return err
			}

		case <-ctx.Done():
			// Контекст отменён — дочитаем всё, что осталось в канале
			for domain := range in {
				if _, err := writer.WriteString(domain + "\n"); err != nil {
					return err
				}
			}
			return ctx.Err() // вернём причину отмены (можно заменить на nil, если не критично)
		}
	}
}

type Result struct {
	URL         string                 `json:"url"`
	Timestamp   string                 `json:"timestamp"`
	Error       string                 `json:"error,omitempty"`
	Fingerprint map[string]interface{} `json:"fingerprint,omitempty"`
	Method      string                 `json:"method"` // passive / wappalyzer
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

	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}

// WappalyzerScan: делает HTTP GET и запускает wappalyzer fingerprint.
// Возвращает fingerprint map (или nil) и ошибку.
// <- заменяем старую функцию, теперь возвращаем map[string]interface{}
func WappalyzerScan(ctx context.Context, client *http.Client, target string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Astarot-WappScan/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB лимит
	if err != nil {
		return nil, err
	}

	wc, err := wapp.New()
	if err != nil || wc == nil {
		return nil, fmt.Errorf("wappalyzer init failed: %v", err)
	}

	// wc.Fingerprint возвращает map[string]struct{}
	raw := wc.Fingerprint(resp.Header, body) // map[string]struct{}

	// Конвертим в map[string]interface{} чтобы потом JSON'ом писать
	fp := make(map[string]interface{}, len(raw))
	for name := range raw {
		fp[name] = true
	}

	return fp, nil
}

func WappalyzerMain() {
	// Параметры
	input := "./tmp/alive.txt"
	output := "Wappalyzer_SCAN.json"
	workers := runtime.NumCPU() * 2
	timeout := 15 * time.Second
	proxy := os.Getenv("PROXY") // например "socks5://127.0.0.1:9050" или "http://127.0.0.1:8080"

	// Читаем список URL'ов
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
		// Гарантируем схему (если без http)
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			line = "http://" + line
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		log.Printf(RED+"[WARN]"+RESET+" reading %s: %v\n", input, err)
	}

	client := newHttpClient(timeout, proxy)

	// Каналы и пул
	jobs := make(chan string, len(targets))
	results := make(chan Result, len(targets))
	var wg sync.WaitGroup

	ctxRoot := context.Background()

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for t := range jobs {
				start := time.Now().UTC()
				ctx, cancel := context.WithTimeout(ctxRoot, timeout+5*time.Second)
				fp, err := WappalyzerScan(ctx, client, t)
				cancel()

				res := Result{
					URL:       t,
					Timestamp: start.Format(time.RFC3339),
					Method:    "wappalyzer",
				}
				if err != nil {
					res.Error = err.Error()
				} else {
					res.Fingerprint = fp
				}
				results <- res
			}
		}(i)
	}

	// Наполняем джобы
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)

	// Ждём завершения воркеров в отдельной горутине и закрываем results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Собираем результаты в мапу/слайс
	out := make([]Result, 0, len(targets))
	for r := range results {
		out = append(out, r)
		// Можно печатать прогресс
		if r.Error != "" {
			log.Printf(RED+"[ERR]"+RESET+" %s -> %s\n", r.URL, r.Error)
		} else {
			log.Printf("[OK] %s -> %v\n", r.URL, r.Fingerprint)
		}
	}

	// Записываем JSON
	of, err := os.Create(output)
	if err != nil {
		log.Fatalf(RED+"[FATAL]"+RESET+" can't create %s: %v\n", output, err)
	}
	enc := json.NewEncoder(of)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		log.Fatalf(RED+"[FATAL]"+RESET+" can't write json: %v\n", err)
	}
	of.Close()

	log.Printf("done. results -> %s\n", output)
}
