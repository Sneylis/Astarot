package passive

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Sneylis/Astarot/core"
)

// Passive выполняет passive reconnaissance и пишет найденные домены в w.
// Дедупликация и alive-check выполняются позже в core.DedupeAndCheckAlive.
func Passive(domain string, w *core.SafeWriter) error {
	fmt.Printf("\n[*] Passive сканирование: %s\n", domain)
	fmt.Println(strings.Repeat("=", 60))

	var allResults []string
	startTime := time.Now()

	// 1. Certificate Transparency (crt.sh)
	fmt.Println("\n[1/6] Проверка Certificate Transparency (crt.sh)...")
	ctResults := getCrtSh(domain)
	allResults = append(allResults, ctResults...)
	fmt.Printf("      └─ Найдено: %d доменов\n", len(ctResults))

	// 2. Certificate Transparency (альтернативный источник — заглушка)
	fmt.Println("\n[2/6] Проверка Censys Certificate Search...")
	censysResults := getCertificateTransparency(domain)
	allResults = append(allResults, censysResults...)
	fmt.Printf("      └─ Найдено: %d доменов\n", len(censysResults))

	// 3. DNS записи (HackerTarget)
	fmt.Println("\n[3/6] Проверка DNS записей (HackerTarget)...")
	dnsResults := getDNSRecords(domain)
	allResults = append(allResults, dnsResults...)
	fmt.Printf("      └─ Найдено: %d доменов\n", len(dnsResults))

	// 4. Web Archive (Wayback Machine)
	fmt.Println("\n[4/6] Проверка Web Archive (Wayback Machine)...")
	archiveResults := getWaybackMachine(domain)
	allResults = append(allResults, archiveResults...)
	fmt.Printf("      └─ Найдено: %d доменов\n", len(archiveResults))

	// 5. SecurityTrails API
	fmt.Println("\n[5/6] Проверка SecurityTrails API...")
	stResults := getSecurityTrails(domain)
	allResults = append(allResults, stResults...)
	fmt.Printf("      └─ Найдено: %d доменов\n", len(stResults))

	// 6. VirusTotal API
	fmt.Println("\n[6/6] Проверка VirusTotal API...")
	vtResults := getVirusTotal(domain)
	allResults = append(allResults, vtResults...)
	fmt.Printf("      └─ Найдено: %d доменов\n", len(vtResults))

	// Записываем все результаты в общий SafeWriter
	for _, result := range allResults {
		if err := w.WriteLine(result); err != nil {
			return fmt.Errorf("ошибка записи: %v", err)
		}
	}

	elapsed := time.Since(startTime)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("\n[✓] Passive завершён за %s\n", elapsed.Round(time.Second))
	fmt.Printf("[+] Всего найдено: %d результатов\n\n", len(allResults))

	return nil
}

// ============================================================================
// 1. Certificate Transparency - crt.sh
// ============================================================================
type CrtShEntry struct {
	NameValue string `json:"name_value"`
}

func getCrtSh(domain string) []string {
	var results []string

	client := createHTTPClient(10 * time.Second)
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("      [!] Ошибка запроса crt.sh: %v\n", err)
		return results
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("      [!] crt.sh вернул код: %d\n", resp.StatusCode)
		return results
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return results
	}

	var entries []CrtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return results
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		domains := strings.Split(entry.NameValue, "\n")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			d = strings.ToLower(d)
			if d != "" && !seen[d] && strings.HasSuffix(d, domain) {
				results = append(results, d)
				seen[d] = true
			}
		}
	}

	return results
}

// ============================================================================
// 2. Certificate Transparency — альтернативный метод (заглушка)
// ============================================================================
func getCertificateTransparency(domain string) []string {
	// TODO: добавить Censys / Facebook CT / Google CT
	return nil
}

// ============================================================================
// 3. DNS Records (HackerTarget)
// ============================================================================
func getDNSRecords(domain string) []string {
	var results []string

	client := createHTTPClient(10 * time.Second)
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)

	resp, err := client.Get(url)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return results
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ",")
		if len(parts) >= 1 {
			subdomain := strings.TrimSpace(parts[0])
			if subdomain != "" && strings.HasSuffix(subdomain, domain) {
				results = append(results, subdomain)
			}
		}
	}

	return results
}

// ============================================================================
// 4. Wayback Machine (Web Archive)
// ============================================================================
func getWaybackMachine(domain string) []string {
	var results []string

	client := createHTTPClient(15 * time.Second)
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain)

	resp, err := client.Get(url)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return results
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return results
	}

	var data [][]string
	if err := json.Unmarshal(body, &data); err != nil {
		return results
	}

	seen := make(map[string]bool)
	domainRegex := regexp.MustCompile(`https?://([a-zA-Z0-9\-\.]+\.)` + regexp.QuoteMeta(domain))

	for _, entry := range data {
		if len(entry) > 0 {
			matches := domainRegex.FindStringSubmatch(entry[0])
			if len(matches) >= 2 {
				subdomain := strings.TrimSuffix(matches[1], ".") + domain
				subdomain = strings.ToLower(subdomain)
				if !seen[subdomain] {
					results = append(results, subdomain)
					seen[subdomain] = true
				}
			}
		}
	}

	return results
}

// ============================================================================
// 5. SecurityTrails API
// ============================================================================
type SecurityTrailsResponse struct {
	Subdomains []string `json:"subdomains"`
}

func getSecurityTrails(domain string) []string {
	var results []string

	apiKey := os.Getenv("SECURITYTRAILS_API_KEY")
	if apiKey == "" {
		fmt.Println("      [!] SECURITYTRAILS_API_KEY не установлен, пропускаем")
		return results
	}

	client := createHTTPClient(10 * time.Second)
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return results
	}

	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("      [!] SecurityTrails вернул код: %d\n", resp.StatusCode)
		return results
	}

	var stResp SecurityTrailsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stResp); err != nil {
		return results
	}

	for _, subdomain := range stResp.Subdomains {
		if subdomain != "" {
			results = append(results, subdomain+"."+domain)
		}
	}

	return results
}

// ============================================================================
// 6. VirusTotal API
// ============================================================================
type VirusTotalResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

func getVirusTotal(domain string) []string {
	var results []string

	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		fmt.Println("      [!] VIRUSTOTAL_API_KEY не установлен, пропускаем")
		return results
	}

	client := createHTTPClient(10 * time.Second)
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=40", domain)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return results
	}

	req.Header.Set("x-apikey", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return results
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("      [!] VirusTotal вернул код: %d\n", resp.StatusCode)
		return results
	}

	var vtResp VirusTotalResponse
	if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
		return results
	}

	for _, item := range vtResp.Data {
		if item.ID != "" && strings.HasSuffix(item.ID, domain) {
			results = append(results, item.ID)
		}
	}

	return results
}

// ============================================================================
// HTTP Client Helper
// ============================================================================
func createHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
