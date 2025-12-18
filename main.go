package main

import (
	"Astarot/recon/active"
	"Astarot/recon/passive"
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	// флаги командной строки (аналог sys.argv)
	domainFlag := flag.String("d", "", "Domain to scan (vhost)")
	useProxyFlag := flag.Bool("proxy", false, "Use proxies from proxies.txt for active scan")
	subdomainsFileFlag := flag.String("sublist", "./subList.txt", "File with subdomain names for active scan (one per line)")
	flag.Parse()

	var domain string
	if *domainFlag != "" {
		domain = *domainFlag
	} else {
		// если домен не передан флагом — спросим у пользователя
		fmt.Printf("Domain: -> ")
		fmt.Scanln(&domain)
	}

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

	// пассивный реконт
	passive.PassiveMain(domain)

	// загрузим субдомены в "dictionary" (map[string]struct{})
	subdomains := make(map[string]struct{})
	f, err := os.Open(*subdomainsFileFlag)
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			// subdomain из файла подставляем в основной domain:
			// line = "www", domain = "example.com" => "www.example.com"
			host := line
			if !strings.HasSuffix(line, "."+domain) {
				host = line + "." + domain
			}
			subdomains[host] = struct{}{}
		}
	}

	// активный реконт с vhost и флагом использования прокси
	fmt.Printf("[ACTIVE] start active subdomain recon for %d targets (proxy=%v)\n", len(subdomains), *useProxyFlag)
	_ = active.Active(domain, 13)
}
