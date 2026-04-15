package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

	"Astarot/core"
	Core "Astarot/core/Analyze"
	cveanalyzer "Astarot/core/CVE"
	jsanalyzer "Astarot/core/Js"
	"Astarot/core/masscan"
	"Astarot/core/report"
	waf "Astarot/core/WafW00f"
	"Astarot/recon/active"
	"Astarot/recon/passive"
	"github.com/joho/godotenv"
)

// ─── ANSI colour palette ──────────────────────────────────────────────────────
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	cyan    = "\033[96m"
	green   = "\033[92m"
	yellow  = "\033[93m"
	red     = "\033[91m"
	blue    = "\033[94m"
	magenta = "\033[95m"
	white   = "\033[97m"
	gray    = "\033[90m"
)

// ─── Banner ───────────────────────────────────────────────────────────────────
const bannerArt = `
  ▄▄▄        ██████ ▄▄▄█████▓ ▄▄▄       ██▀███   ▒█████  ▄▄▄█████▓
  ▒████▄    ▒██    ▒ ▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒▒██▒  ██▒▓  ██▒ ▓▒
  ▒██  ▀█▄  ░ ▓██▄   ▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒▒██░  ██▒▒ ▓██░ ▒░
  ░██▄▄▄▄██   ▒   ██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  ▒██   ██░░ ▓██▓ ░
   ▓█   ▓██▒▒██████▒▒  ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒░ ████▓▒░  ▒██▒ ░
   ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░▒░▒░   ▒ ░░
    ▒   ▒▒ ░░ ░▒  ░ ░    ░      ▒   ▒▒ ░  ░▒ ░ ▒░  ░ ▒ ▒░     ░
    ░   ▒   ░  ░  ░    ░        ░   ▒     ░░   ░ ░ ░ ░ ▒    ░
        ░  ░      ░                 ░  ░   ░         ░ ░`

func printBanner() {
	fmt.Println(cyan + bold + bannerArt + reset)
	fmt.Printf("%s%s%s  %-20s%s%s\n",
		gray, "  ─────────────────────────────────────────────────────────────", reset,
		"",
		"",
		"",
	)
	fmt.Printf("  %sRecon Framework%s  %s·%s  %sv0.5%s\n\n",
		white+bold, reset,
		gray, reset,
		cyan+bold, reset,
	)
}

// ─── Help card ────────────────────────────────────────────────────────────────
func printHelp() {
	printBanner()
	w := 66
	line := func(s string) { fmt.Printf("  %s│%s %-*s %s│%s\n", cyan, reset, w, s, cyan, reset) }
	sep := func() { fmt.Printf("  %s├%s%s%s┤%s\n", cyan, cyan, repeat("─", w+2), cyan, reset) }
	top := func() { fmt.Printf("  %s┌%s%s%s┐%s\n", cyan, cyan, repeat("─", w+2), cyan, reset) }
	bot := func() { fmt.Printf("  %s└%s%s%s┘%s\n", cyan, cyan, repeat("─", w+2), cyan, reset) }

	top()
	line(bold + white + "  ASTAROT  ·  Help" + reset)
	sep()
	line("")
	line(yellow + bold + "  Usage:" + reset)
	line("    astarot " + dim + "[flags]" + reset + " " + white + "<domain>" + reset)
	line("")
	sep()
	line(yellow + bold + "  Flags:" + reset)
	line("")
	line(fmt.Sprintf("    %s--Wsub%s    <file>  %sSubdomain wordlist%s    %s(default: subList.txt)%s",
		green+bold, reset, white, reset, gray, reset))
	line(fmt.Sprintf("    %s--Wproxy%s  <file>  %sProxy list file%s       %s(default: proxies.txt)%s",
		green+bold, reset, white, reset, gray, reset))
	line(fmt.Sprintf("    %s-h%s, %s--help%s          %sShow this help%s",
		green+bold, reset, green+bold, reset, white, reset))
	line("")
	sep()
	line(yellow + bold + "  Examples:" + reset)
	line("")
	line("    astarot " + cyan + "example.com" + reset)
	line("    astarot " + green + "--Wsub" + reset + " /opt/wordlists/subdomains.txt " + cyan + "example.com" + reset)
	line("    astarot " + green + "--Wproxy" + reset + " proxyies.txt " + cyan + "example.com" + reset)
	line("")
	bot()
	fmt.Println()
}

// ─── Phase helpers ────────────────────────────────────────────────────────────
func phaseHeader(n int, title string) {
	label := fmt.Sprintf("[ Phase %d ]", n)
	bar := repeat("─", 50)
	fmt.Printf("\n  %s%s%s%s%s %s%s%s\n",
		blue+bold, "┌─", reset,
		cyan+bold, label, reset,
		gray, bar+reset,
	)
	fmt.Printf("  %s│%s  %s%s%s\n", blue, reset, white+bold, title, reset)
	fmt.Printf("  %s└%s%s\n\n", blue, gray, repeat("─", 58)+reset)
}

func phaseOK(n int, msg string) {
	fmt.Printf("\n  %s[✔]%s %sPhase %d%s  %s%s%s\n",
		green+bold, reset,
		cyan+bold, n, reset,
		white, msg, reset,
	)
}

func info(icon, msg string) {
	fmt.Printf("  %s%s%s  %s\n", gray, icon, reset, msg)
}

func ok(msg string) {
	fmt.Printf("  %s[✔]%s  %s\n", green+bold, reset, msg)
}

func warn(msg string) {
	fmt.Printf("  %s[!]%s  %s%s%s\n", yellow+bold, reset, yellow, msg, reset)
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

// ─── Summary card ─────────────────────────────────────────────────────────────
func printSummary(domain, resultFile, portsFile, wappalyzerFile, reportFile string, aliveCount int) {
	w := 54
	line := func(k, v string) {
		fmt.Printf("  %s│%s  %-18s %s%-*s%s  %s│%s\n",
			cyan, reset,
			yellow+k+reset,
			white, w-20, v, reset,
			cyan, reset,
		)
	}
	top := func() { fmt.Printf("  %s┌%s%s%s┐%s\n", cyan, cyan, repeat("─", w+2), cyan, reset) }
	sep := func() { fmt.Printf("  %s├%s%s%s┤%s\n", cyan, cyan, repeat("─", w+2), cyan, reset) }
	bot := func() { fmt.Printf("  %s└%s%s%s┘%s\n", cyan, cyan, repeat("─", w+2), cyan, reset) }
	hdr := func(s string) {
		fmt.Printf("  %s│%s %s%-*s%s %s│%s\n", cyan, reset, white+bold, w, s, reset, cyan, reset)
	}

	fmt.Println()
	top()
	hdr("  Scan complete  ·  " + cyan + domain + reset + white+bold)
	sep()
	line("Target:", domain)
	line("Alive hosts:", fmt.Sprintf("%s%d%s", green+bold, aliveCount, reset))
	sep()
	line("Domains:", resultFile)
	line("Ports:", portsFile)
	line("WAF:", "out/waf/")
	line("Wappalyzer:", wappalyzerFile)
	line("Report:", green+bold+reportFile+reset)
	bot()
	fmt.Println()
}

// ─── Entry point ──────────────────────────────────────────────────────────────
func main() {
	// Parse flags before printing banner so --help works cleanly
	helpShort := flag.Bool("h", false, "")
	helpLong := flag.Bool("help", false, "")
	wordlist  := flag.String("Wsub",   "subList.txt",  "Wordlist for subdomain bruteforce")
	proxyFile := flag.String("Wproxy", "proxies.txt",  "Proxy list file (socks5:// or http://)")

	flag.Usage = func() { printHelp() }
	flag.Parse()

	if *helpShort || *helpLong {
		printHelp()
		os.Exit(0)
	}

	printBanner()

	_ = godotenv.Load()

	args := flag.Args()
	if len(args) < 1 {
		warn("No target domain specified.")
		fmt.Printf("  %sUsage:%s  astarot %s[flags]%s %s<domain>%s\n",
			yellow+bold, reset, gray, reset, white+bold, reset)
		fmt.Printf("  Run %sastarot --help%s for more information.\n\n",
			cyan+bold, reset)
		os.Exit(1)
	}

	domain := args[0]

	fmt.Printf("  %sTarget%s    %s→%s  %s%s%s\n",  yellow+bold, reset, gray, reset, cyan+bold, domain, reset)
	fmt.Printf("  %sWordlist%s  %s→%s  %s%s%s\n",  yellow+bold, reset, gray, reset, white, *wordlist, reset)
	fmt.Printf("  %sProxies%s   %s→%s  %s%s%s\n\n", yellow+bold, reset, gray, reset, white, *proxyFile, reset)
	fmt.Printf("  %s%s%s\n", gray, repeat("─", 60), reset)

	// Create output dirs
	for _, dir := range []string{"tmp", "out/waf"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Cannot create directory %s: %v", dir, err)
		}
	}

	const (
		rawFile        = "tmp/raw_result.txt"
		resultFile     = "tmp/result.txt"
		portsFile      = "tmp/Ports.txt"
		wappalyzerFile = "tmp/Wappalyzer.json"
	)

	// ── Phase 1: Proxy check ──────────────────────────────────────────────────
	phaseHeader(0, "Proxy validation")
	info("→", "Checking proxies…")
	proxies, runBrute := active.PrepareProxies(*proxyFile)

	// ── Phase 1: Passive + Active (parallel) ──────────────────────────────────
	phaseHeader(1, "Passive OSINT  +  Active bruteforce  (parallel)")

	w, err := core.NewSafeWriter(rawFile)
	if err != nil {
		log.Fatalf("Cannot create %s: %v", rawFile, err)
	}

	var phase1 sync.WaitGroup
	phase1.Add(2)

	go func() {
		defer phase1.Done()
		if err := passive.Passive(domain, w); err != nil {
			log.Printf("[passive] %v", err)
		}
	}()

	go func() {
		defer phase1.Done()
		if err := active.Active(domain, 10, w, proxies, runBrute, *wordlist); err != nil {
			log.Printf("[active] %v", err)
		}
	}()

	phase1.Wait()

	if err := w.Close(); err != nil {
		log.Printf("raw_result close error: %v", err)
	}
	phaseOK(1, "Subdomain collection finished.")

	// ── Phase 2: Dedup + alive check ─────────────────────────────────────────
	phaseHeader(2, "Deduplication  +  Alive check")
	info("→", "Processing raw results…")

	if err := core.DedupeAndCheckAlive(rawFile, resultFile, *proxyFile); err != nil {
		log.Fatalf("[phase 2] %v", err)
	}

	count, _ := core.GetStats(resultFile)
	phaseOK(2, fmt.Sprintf("Alive hosts: %s%d%s  →  %s%s%s",
		green+bold, count, reset,
		white, resultFile, reset,
	))

	// ── Phase 3: Masscan + WAF + Wappalyzer (parallel) ───────────────────────
	phaseHeader(3, "Masscan  +  WAF detection  +  Wappalyzer  (parallel)")

	var phase3 sync.WaitGroup
	phase3.Add(3)

	go func() {
		defer phase3.Done()
		info("→", "Masscan port scan…")
		if err := masscan.Scan(resultFile, portsFile); err != nil {
			log.Printf("[masscan] %v", err)
		} else {
			ok("Masscan complete.")
		}
	}()

	go func() {
		defer phase3.Done()
		info("→", "WAF detection…")
		waf.Wafw00fMain(resultFile)
		ok("WAF detection complete.")
	}()

	go func() {
		defer phase3.Done()
		info("→", "Wappalyzer fingerprinting…")
		Core.WappalyzerMain(resultFile, wappalyzerFile)
		ok("Wappalyzer complete.")
	}()

	phase3.Wait()
	phaseOK(3, "All parallel modules finished.")

	// ── Phase 4: JS Analysis + CVE Scan (parallel) ───────────────────────────
	phaseHeader(4, "JS Analysis  +  CVE Scan  (parallel)")

	proxyURLs := make([]string, len(proxies))
	for i, p := range proxies {
		proxyURLs[i] = p.URL
	}

	var phase4 sync.WaitGroup
	phase4.Add(2)

	go func() {
		defer phase4.Done()
		info("→", "JS analysis (passive OSINT + crawl + brute + recursive)…")
		jsanalyzer.JSAnalyzerMain(resultFile, proxyURLs, "tmp")
		ok("JS analysis complete.")
	}()

	go func() {
		defer phase4.Done()
		info("→", "CVE scan (NVD API)…")
		cveanalyzer.CVEMain(wappalyzerFile, proxyURLs, "tmp")
		ok("CVE scan complete.")
	}()

	phase4.Wait()
	phaseOK(4, "JS analysis and CVE scan finished.")

	// ── Phase 5: HTML report ─────────────────────────────────────────────────
	phaseHeader(5, "HTML report generation")
	reportFile := "report.html"

	r, err := report.Build(domain, wappalyzerFile, portsFile, "out/waf")
	if err != nil {
		log.Printf("[report] Build error: %v", err)
	} else if err := report.GenerateHTML(r, reportFile); err != nil {
		log.Printf("[report] HTML error: %v", err)
	} else {
		ok(fmt.Sprintf("Report saved  →  %s%s%s", green+bold, reportFile, reset))
	}
	phaseOK(5, "Done.")

	// ── Summary ───────────────────────────────────────────────────────────────
	printSummary(domain, resultFile, portsFile, wappalyzerFile, reportFile, count)
}
