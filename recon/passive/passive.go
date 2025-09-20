// recon/passive/passive.go
package passive

import (
	core "Astarot/core/Analyze" // <— поправь путь под свой module
	probe "Astarot/core/Checker"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Workers    int
	Timeout    time.Duration
	UserAgent  string
	MaxRetries int
}

var cfg = Config{
	Workers:    10,
	Timeout:    10 * time.Second,
	UserAgent:  "Mozilla/5.0 (compatible; MyScanner/1.0)",
	MaxRetries: 1,
}

const (
	RED   = "\033[31m"
	GREEN = "\033[32m"
	RESET = "\033[0m"
)

func Passvie_Url_Crt_sh(ctx context.Context, domain string, out chan<- string) {

	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Println(err)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf(RED+"[ERROR]"+RESET+" Crt.sh return error: %d, resp: %s", resp.StatusCode, body)
		return
	}

	var results []struct {
		Name string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[ERROR] parse JSON: %s, resp: %s", err, body)
		return
	}

	for _, r := range results {
		if strings.HasPrefix(r.Name, "*") {
			continue
		}
		select {
		case out <- r.Name:
		case <-ctx.Done():
			return
		}
	}
	fmt.Println(GREEN + "[INFO]" + RESET + " Crt.sh done")
}

func FetchSecTrails(ctx context.Context, domain string, out chan<- string) {

	// --- конфиг / API key ---
	type Config struct {
		APIKey string `json:"api_key"`
	}

	key := os.Getenv("SECURITYTRAILS_API_KEY")
	if key == "" {
		data, err := os.ReadFile("config.json")
		if err == nil {
			var c Config
			if err := json.Unmarshal(data, &c); err == nil {
				key = strings.TrimSpace(c.APIKey)
			}
		}
	}
	if key == "" {
		log.Println(RED + "[ERROR]" + RESET + " SecurityTrails API key not found (env SECURITYTRAILS_API_KEY or config.json)")
		return
	}

	// --- HTTP запрос ---
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Println(RED+"[ERROR]"+RESET, "build request:", err)
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("APIKEY", key)
	req.Header.Set("User-Agent", "Astarot/1.0 (+passive)")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Проверим: не отменён ли контекст
		select {
		case <-ctx.Done():
			return
		default:
		}
		log.Println(RED+"[ERROR]"+RESET, "request failed:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		log.Printf(RED+"[ERROR]"+RESET+" bad status from SecurityTrails: %d; body: %s", resp.StatusCode, strings.TrimSpace(string(b)))
		return
	}

	var results struct {
		Subdomains []string `json:"subdomains"`
		Error      string   `json:"error"`
		// иногда приходит поле message
		Message string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		log.Println(RED+"[ERROR]"+RESET, "decode JSON:", err)
		return
	}
	if results.Error != "" || results.Message != "" {
		log.Printf(RED+"[ERROR]"+RESET+" API error: %s %s", results.Error, results.Message)
		return
	}

	for _, sub := range results.Subdomains {
		if sub == "" {
			continue
		}
		full := sub + "." + domain
		select {
		case out <- full:
		case <-ctx.Done():
			return
		}
	}
	fmt.Println(GREEN + "[INFO]" + RESET + " SecurityTrails done")
}

func PassiveMain(domain string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	subdomains := make(chan string)
	uniqueSubdomains := core.ClearDuplicate(subdomains)
	alive := make(chan string)

	var fetchersWG sync.WaitGroup
	fetchersWG.Add(2)

	go func() {
		defer fetchersWG.Done()
		Passvie_Url_Crt_sh(ctx, domain, subdomains)
	}()
	go func() {
		defer fetchersWG.Done()
		FetchSecTrails(ctx, domain, subdomains)
	}()

	// ВАЖНО: закрываем канал, когда оба продюсера закончат
	go func() {
		fetchersWG.Wait()
		close(subdomains)
	}()

	if err := core.SaveResults(ctx, uniqueSubdomains, "./tmp/raw.txt"); err != nil {
		log.Println(RED+"[ERROR]"+RESET, "save alive:", err)
	}

	go func() {
		// proxies.txt — файл с проксями (может не существовать: тогда без прокси)
		cfg := probe.DefaultAliveConfig()
		// пример: хотим 120 воркеров и проверять ещё "/health"
		cfg.Concurrency = 120
		cfg.Paths = []string{"/", "/health"}

		if err := probe.IS_allive(ctx, "./tmp/raw.txt", "./proxies.txt", alive, cfg); err != nil {
			log.Println(RED+"[ERROR]"+RESET, "IS_allive:", err)
		}
	}()

	if err := core.SaveResults(ctx, alive, "./tmp/alive.txt"); err != nil {
		log.Println(RED+"[ERROR]"+RESET, "save alive:", err)
	}
}
