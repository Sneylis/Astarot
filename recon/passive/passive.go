package passive

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

// --------------------  Crt.sh Finder func ---------------------- //

type CertEntry struct {
	Name string `json:"name_value"`
}

func FindCertSh(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)

	// Добавляем User-Agent, чтобы нас не блокировали
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Astarot/1.0; +https://github.com/yourrepo)")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Проверяем статус-код
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body) // Читаем тело ответа для отладки
		return nil, fmt.Errorf("Crt.sh вернул ошибку: %d, ответ: %s", resp.StatusCode, body)
	}

	// Парсим JSON
	var results []struct {
		Name string `json:"name_value"`
	}
	err = json.NewDecoder(resp.Body).Decode(&results)
	if err != nil {
		body, _ := io.ReadAll(resp.Body) // Читаем тело ответа
		return nil, fmt.Errorf("Ошибка при разборе JSON: %s, Ответ: %s", err, body)
	}

	// Извлекаем поддомены
	var subdomains []string
	for _, r := range results {
		if !strings.HasPrefix(r.Name, "*.") {
			subdomains = append(subdomains, r.Name)
		}
	}

	return subdomains, nil
}

// ---------------------------- SecurityTrails Finder Func ------------------------------//

type SecurityTrailsResponse struct {
	Subdomains []string `json:"subdomains"`
}

func FindSecTrails(domain, API_KEY string) ([]string, error) {
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("APIKEY", API_KEY)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result SecurityTrailsResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	var subdomains []string
	for _, sub := range result.Subdomains {
		subdomains = append(subdomains, fmt.Sprintf("%s.%s", sub, domain))
	}

	return subdomains, nil
}
