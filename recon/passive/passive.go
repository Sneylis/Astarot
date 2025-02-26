package passive

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type CertEntry struct {
	Name string `json:"name_value"`
}

func FindCertSh(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []CertEntry
	err = json.Unmarshal(body, &entries)
	if err != nil {
		return nil, err
	}

	subdomainsMap := make(map[string]bool)
	var subdomains []string
	for _, entry := range entries {
		for _, sub := range strings.Split(entry.Name, "\n") {
			if _, exists := subdomainsMap[sub]; !exists {
				subdomains = append(subdomains, sub)
				subdomainsMap[sub] = true
			}
		}
	}
	return subdomains, nil
}

func main() {
	var domain string
	fmt.Printf("Type the domain: ")
	fmt.Scanf("%s\n", &domain)
	subdomains, err := FindCertSh(domain)
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	fmt.Println("Finded Subdomains: ", subdomains)
}
