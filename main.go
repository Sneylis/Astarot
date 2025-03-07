package main

import (
	"Astarot/recon/passive"
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"
)

const workerCount = 10

func checkURL(domain string, wg *sync.WaitGroup, results chan<- string) {
	defer wg.Done()

	client := http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Get("http://" + domain)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	results <- fmt.Sprintf("%s -> %d", domain, resp.StatusCode)
}

func processUrl(subdomains []string) {
	var wg sync.WaitGroup
	results := make(chan string, len(subdomains))

	sem := make(chan struct{}, workerCount)

	for _, domain := range subdomains {
		wg.Add(1)
		sem <- struct{}{}
		go func(domain string) {
			defer func() { <-sem }()
			checkURL(domain, &wg, results)
		}(domain)
	}

	wg.Wait()
	close(results)

	for results := range results {
		fmt.Println(results)
	}

}

func saveToFile(filename string, subdomains map[string]bool) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}

	defer file.Close()

	writer := bufio.NewWriter(file)
	for sub := range subdomains {
		_, err := writer.WriteString(sub + "\n")
		if err != nil {
			return err
		}
	}

	return writer.Flush()
}

type Config struct {
	APIKey string `json:"api_key"`
}

func GetAPIKeys() string {
	data, err := ioutil.ReadFile("config.json")
	if err != nil {
		log.Fatal("[ERROR] to read config.json", err)
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Fatal("[ERROR] to read JSON", err)
	}

	if config.APIKey == "" {
		log.Fatal("[ERROR] API key not found !", err)
	}

	return config.APIKey

}

func startPassive(domain string) []string {

	var subdomains []string
	var AliveSub []string

	api_key := GetAPIKeys()
	if api_key == "" {
		fmt.Println("Cant Find API_Key")
		return nil
	}

	subdomainsCrt, err := passive.FindCertSh(domain)
	if err != nil {
		fmt.Println("ERROR with Crt.sh", err)
		return nil
	}

	subdomainSecTrails, err := passive.FindSecTrails(domain, GetAPIKeys())
	if err != nil {
		fmt.Println("ERROR with SecurityTrails", err)
		return nil
	}

	subdomains = append(subdomains, subdomainsCrt...)
	subdomains = append(subdomains, subdomainSecTrails...)

	slices.Sort(subdomains)
	subdomains = slices.Compact(subdomains)

	for _, domain := range subdomains {
		resp, err := http.Get("http://" + domain)
		if err != nil {
			fmt.Println("Error to connect", "http://"+domain)
			continue
		}
		defer resp.Body.Close()
		fmt.Println(domain, "->", resp.StatusCode)
		AliveSub = append(AliveSub, domain)
	}

	return AliveSub
}

func main() {
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

	PassiveRes := startPassive(domain)
	processUrl(PassiveRes)
}
