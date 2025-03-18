package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

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

	client := &http.Client{Timeout: 10 * time.Second}
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

	client := &http.Client{Timeout: 10 * time.Second}
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
