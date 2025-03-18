package main

import (
	"Astarot/core"
	"Astarot/recon/passive"
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//banner
	var domain string
	banner := `

	▄▄▄        ██████ ▄▄▄█████▓ ▄▄▄       ██▀███   ▒█████  ▄▄▄█████▓
	▒████▄    ▒██    ▒ ▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒▒██▒  ██▒▓  ██▒ ▓▒
	▒██  ▀█▄  ░ ▓██▄   ▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒▒██░  ██▒▒ ▓██░ ▒░
	░██▄▄▄▄██   ▒   ██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  ▒██   ██░░ ▓██▓ ░
	▓█   ▓██▒▒██████▒▒  ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒░ ████▓▒░  ▒██▒ ░
	▒▒   ▓▒█░▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░▒░▒░   ▒ ░░
	▒   ▒▒ ░░ ░▒  ░ ░    ░      ▒   ▒▒ ░  ░▒ ░ ▒░  ░ ▒ ▒░     ░
	░   ▒   ░  ░  ░    ░        ░   ▒     ░░   ░ ░ ░ ░ ▒    ░
		░  ░      ░                 ░  ░   ░         ░ ░

			Recon tool - Astarot v1.0`
	fmt.Println(banner)
	fmt.Printf("Domain: -> ")
	fmt.Scanln(&domain)

	// Инициализируем каналы
	subdomains := make(chan string)
	uniqueSubdomains := core.ClearDuplicate(subdomains)
	checkedDomains := make(chan string)

	// Запускаем сбор данных
	var fetchersWG sync.WaitGroup
	fetchersWG.Add(2)
	go func() {
		defer fetchersWG.Done()
		passive.FetchCrtSH(ctx, domain, subdomains)
	}()
	go func() {
		defer fetchersWG.Done()
		passive.FetchSecTrails(ctx, domain, subdomains)
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

	log.Println("Scan completed successfully")
}

func checkDomains(ctx context.Context, in <-chan string, out chan<- string, workerID int) {
	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  true,
			MaxIdleConnsPerHost: 10,
		},
	}

	for domain := range in {
		select {
		case <-ctx.Done():
			return
		default:
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

// func main() {
// 	var domain string
// 	banner := `

//  ▄▄▄        ██████ ▄▄▄█████▓ ▄▄▄       ██▀███   ▒█████  ▄▄▄█████▓
// ▒████▄    ▒██    ▒ ▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒▒██▒  ██▒▓  ██▒ ▓▒
// ▒██  ▀█▄  ░ ▓██▄   ▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒▒██░  ██▒▒ ▓██░ ▒░
// ░██▄▄▄▄██   ▒   ██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  ▒██   ██░░ ▓██▓ ░
//  ▓█   ▓██▒▒██████▒▒  ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒░ ████▓▒░  ▒██▒ ░
//  ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░▒░▒░   ▒ ░░
//   ▒   ▒▒ ░░ ░▒  ░ ░    ░      ▒   ▒▒ ░  ░▒ ░ ▒░  ░ ▒ ▒░     ░
//   ░   ▒   ░  ░  ░    ░        ░   ▒     ░░   ░ ░ ░ ░ ▒    ░
//       ░  ░      ░                 ░  ░   ░         ░ ░

// 		Recon tool - Astarot v1.0`
// 	fmt.Println(banner)
// 	fmt.Printf("Domain: -> ")
// 	fmt.Scanln(&domain)

// 	passive.Passive(domain, "res.txt")
// }
