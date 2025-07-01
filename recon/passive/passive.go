package passive

import (
	core "Astarot/core/Analyze"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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
	Red   = "\033[31m"
	Green = "\033[32m"
	Reset = "\033[0m"
)

func FetchCrtSH(ctx context.Context, domain string, out chan<- string) {

	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	defer close(out)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf(Red+"[ERROR]"+Reset+"Crt.sh return error: %d, resp: %s", resp.StatusCode, body)
		return
	}

	var results []struct {
		Name string `json:"name_value"`
	}

	err = json.NewDecoder(resp.Body).Decode(&results)
	if err != nil {
		body, _ := io.ReadAll(resp.Body)
		log.Printf(Red+"[ERROR]"+Reset+" parse JSON: %s, resp: %s", err, body)
		return
	}

	for _, r := range results {
		select {
		case out <- r.Name:
		case <-ctx.Done(): // Прерываем отправку при отмене контекста
			return

		}
		if !strings.HasPrefix(r.Name, "*") {
			out <- r.Name
		}
	}
}

func FetchSecTrails(ctx context.Context, domain string, out chan<- string) {

	type Config struct {
		ApiKey string `json:"api_key"`
	}

	data, err := ioutil.ReadFile("config.json")
	if err != nil {
		log.Fatal(Red + "[ERROR]" + Reset + " config.json not exist\nPlease Create config.json on these direcotry and write {\"api_key\":\"API-Key from SecurityTrails API\"}")
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil || config.ApiKey == "" {
		log.Fatal(Red + "[ERROR]" + Reset + "API key not found\nPlease Create config.json on these direcotry and write {\"api_key\":\"API-Key from SecurityTrails API\"}")
	}

	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(Red+"[ERROR]"+Reset, err)
		return
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("APIKEY", config.ApiKey)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(Red+"[ERROR]"+Reset, "Request failed", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf(Red+"[ERROR]"+Reset, "Bad Status code to connect SecurityTrlais: %d", resp.StatusCode)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf(Red+"[ERROR]"+Reset, "reading response %v", err)
		return
	}

	var results struct {
		Subdomains []string `json:"subdomains"`
		Error      string   `json:"error"`
	}

	if err := json.Unmarshal(body, &results); err != nil {
		log.Printf(Red+"[ERROR]"+Reset, "JSON decode error %v", err)
		return
	}

	if results.Error != "" {
		log.Printf(Red+"[ERROR]"+Reset, "API eror %s", results.Error)
		return
	}

	for _, sub := range results.Subdomains {
		fullDomain := fmt.Sprintf("%s.%s", sub, domain)
		select {
		case out <- fullDomain:
		case <-ctx.Done(): // Прерываем отправку при отмене контекста
			return
		}
	}

}

func checkDomains(ctx context.Context, in <-chan string, out chan<- string, workerID int) {

	for domain := range in {
		select {
		case <-ctx.Done():
			return
		default:
			client := &http.Client{
				Timeout: 10 * time.Second,
			}
			if checkDomain(ctx, client, domain, workerID) {
				out <- domain
			}
		}
	}
}

func checkDomain(ctx context.Context, client *http.Client, domain string, workerID int) bool {
	url := "http://" + domain

	for attempt := 1; attempt <= cfg.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			log.Printf("[W%d] Error creating request: %v", workerID, err)
			return false
		}
		req.Header.Set("User-Agent", cfg.UserAgent)

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[W%d] Attempt %d/%d for %s: %v",
				workerID, attempt, cfg.MaxRetries, domain, err)
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		duration := time.Since(start)
		log.Printf("[W%d] %s - Status: %d, Length: %d, Duration: %s",
			workerID, domain, resp.StatusCode, len(body), duration.Round(time.Millisecond))

		// Считаем успешными статусы 2xx и 3xx
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return true
		}
	}
	return false
}

func saveResults(ctx context.Context, in <-chan string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case domain, ok := <-in:
			if !ok {
				return nil
			}
			if _, err := writer.WriteString(domain + "\n"); err != nil {
				return err
			}
		}
	}
}

func PassiveMain(domain string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//banner
	// Инициализируем каналы
	subdomains := make(chan string)
	uniqueSubdomains := core.ClearDuplicate(subdomains)
	checkedDomains := make(chan string)

	// Запускаем сбор данных
	var fetchersWG sync.WaitGroup
	fetchersWG.Add(2)
	go func() {
		defer fetchersWG.Done()
		FetchCrtSH(ctx, domain, subdomains)
	}()
	go func() {
		defer fetchersWG.Done()
		FetchSecTrails(ctx, domain, subdomains)
	}()

	// Закрываем канал subdomains после завершения всех сборщиков
	go func() {
		fetchersWG.Wait()
	}()

	// Запускаем проверку доменов
	var checkerWG sync.WaitGroup
	checkerWG.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go func(id int) {
			defer checkerWG.Done()
			checkDomains(ctx, uniqueSubdomains, checkedDomains, id)
		}(i + 1)
	}

	// Запускаем запись результатов
	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		saveResults(ctx, checkedDomains, "live_domains.txt")
	}()

	// Ожидаем завершения всех компонентов
	checkerWG.Wait()
	close(checkedDomains)
	writerWG.Wait()
}
