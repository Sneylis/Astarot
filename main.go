package main

import (
	"Astarot/recon/passive"
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

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

func startPassive(domain string) {

	subdomainsCrt, err := passive.FindCertSh(domain)
	if err != nil {
		fmt.Println(err)
	}

	subdomainSecTrails, err := passive.FindSecTrails(domain, GetAPIKeys())
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(subdomainsCrt)
	fmt.Println(subdomainSecTrails)
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

	startPassive(domain)
}
