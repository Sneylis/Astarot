package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"Astarot/core"
	Core "Astarot/core/Analyze"
	"Astarot/core/masscan"
	"Astarot/core/report"
	waf "Astarot/core/WafW00f"
	"Astarot/recon/active"
	"Astarot/recon/passive"
	"github.com/joho/godotenv"
)

const banner = `
  ▄▄▄        ██████ ▄▄▄█████▓ ▄▄▄       ██▀███   ▒█████  ▄▄▄█████▓
  ▒████▄    ▒██    ▒ ▓  ██▒ ▓▒▒████▄    ▓██ ▒ ██▒▒██▒  ██▒▓  ██▒ ▓▒
  ▒██  ▀█▄  ░ ▓██▄   ▒ ▓██░ ▒░▒██  ▀█▄  ▓██ ░▄█ ▒▒██░  ██▒▒ ▓██░ ▒░
  ░██▄▄▄▄██   ▒   ██▒░ ▓██▓ ░ ░██▄▄▄▄██ ▒██▀▀█▄  ▒██   ██░░ ▓██▓ ░
   ▓█   ▓██▒▒██████▒▒  ▒██▒ ░  ▓█   ▓██▒░██▓ ▒██▒░ ████▓▒░  ▒██▒ ░
   ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░  ▒ ░░    ▒▒   ▓▒█░░ ▒▓ ░▒▓░░ ▒░▒░▒░   ▒ ░░
    ▒   ▒▒ ░░ ░▒  ░ ░    ░      ▒   ▒▒ ░  ░▒ ░ ▒░  ░ ▒ ▒░     ░
    ░   ▒   ░  ░  ░    ░        ░   ▒     ░░   ░ ░ ░ ░ ▒    ░
        ░  ░      ░                 ░  ░   ░         ░ ░

                  Recon tool - Astarot v0.5`

func main() {
	fmt.Println(banner)

	// Загружаем .env если существует (ошибку игнорируем — файл необязателен)
	_ = godotenv.Load()

	if len(os.Args) < 2 {
		fmt.Println("\nUsage: astarot <domain>")
		fmt.Println("Example: astarot example.com")
		os.Exit(1)
	}

	domain := os.Args[1]
	fmt.Printf("\nTarget: %s\n", domain)
	fmt.Println("================================================")

	// Создаём выходные директории
	for _, dir := range []string{"tmp", "out/waf"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("Не удалось создать директорию %s: %v", dir, err)
		}
	}

	const (
		rawFile        = "tmp/raw_result.txt"
		resultFile     = "tmp/result.txt"
		portsFile      = "tmp/Ports.txt"
		wappalyzerFile = "tmp/Wappalyzer.json"
	)

	// ─────────────────────────────────────────────────────────────
	// Предподготовка: проверка прокси (до горутин, интерактивно)
	// ─────────────────────────────────────────────────────────────
	fmt.Println("\n[Подготовка] Проверка прокси...")
	proxies, runBrute := active.PrepareProxies()

	// ─────────────────────────────────────────────────────────────
	// Фаза 1: Passive + Active брутфорс (параллельно)
	// Оба пишут в один файл raw_result.txt через SafeWriter.
	// ─────────────────────────────────────────────────────────────
	fmt.Println("\n[Фаза 1] Passive сбор + Active брутфорс (параллельно)")

	w, err := core.NewSafeWriter(rawFile)
	if err != nil {
		log.Fatalf("Не удалось создать %s: %v", rawFile, err)
	}

	var phase1 sync.WaitGroup
	phase1.Add(2)

	go func() {
		defer phase1.Done()
		if err := passive.Passive(domain, w); err != nil {
			log.Printf("[1.1] Passive ошибка: %v", err)
		}
	}()

	go func() {
		defer phase1.Done()
		if err := active.Active(domain, 10, w, proxies, runBrute); err != nil {
			log.Printf("[1.2] Active ошибка: %v", err)
		}
	}()

	phase1.Wait()

	if err := w.Close(); err != nil {
		log.Printf("Ошибка закрытия raw_result.txt: %v", err)
	}
	fmt.Println("\n[Фаза 1] Завершена.")

	// ─────────────────────────────────────────────────────────────
	// Фаза 2: Дедупликация + проверка живых хостов
	// Читает raw_result.txt → пишет result.txt.
	// ─────────────────────────────────────────────────────────────
	fmt.Println("\n[Фаза 2] Дедупликация и alive-check...")

	if err := core.DedupeAndCheckAlive(rawFile, resultFile, "proxies.txt"); err != nil {
		log.Fatalf("[Фаза 2] Ошибка: %v", err)
	}

	count, _ := core.GetStats(resultFile)
	fmt.Printf("[Фаза 2] Готово. Живых хостов: %d → %s\n", count, resultFile)

	// ─────────────────────────────────────────────────────────────
	// Фаза 3: Masscan + WAF + Wappalyzer (параллельно)
	// Все три модуля читают result.txt.
	// ─────────────────────────────────────────────────────────────
	fmt.Println("\n[Фаза 3] Masscan + WAF + Wappalyzer (параллельно)")

	var phase3 sync.WaitGroup
	phase3.Add(3)

	go func() {
		defer phase3.Done()
		fmt.Println("[1.4] Запуск masscan...")
		if err := masscan.Scan(resultFile, portsFile); err != nil {
			log.Printf("[1.4] Masscan ошибка: %v", err)
		}
	}()

	go func() {
		defer phase3.Done()
		fmt.Println("[1.5] Запуск WAF детектора...")
		waf.Wafw00fMain(resultFile)
	}()

	go func() {
		defer phase3.Done()
		fmt.Println("[1.6] Запуск Wappalyzer...")
		Core.WappalyzerMain(resultFile, wappalyzerFile)
	}()

	phase3.Wait()

	// ─────────────────────────────────────────────────────────────
	// Фаза 4: Генерация HTML-отчёта
	// Объединяет Wappalyzer + masscan + WAF в один report.html
	// ─────────────────────────────────────────────────────────────
	fmt.Println("\n[Фаза 4] Генерация HTML-отчёта...")
	reportFile := "report.html"

	r, err := report.Build(domain, wappalyzerFile, portsFile, "out/waf")
	if err != nil {
		log.Printf("[Фаза 4] Ошибка сборки отчёта: %v", err)
	} else if err := report.GenerateHTML(r, reportFile); err != nil {
		log.Printf("[Фаза 4] Ошибка генерации HTML: %v", err)
	} else {
		fmt.Printf("[Фаза 4] Отчёт сохранён → %s\n", reportFile)
	}

	fmt.Println("\n================================================")
	fmt.Println("Сканирование завершено!")
	fmt.Printf("  Домены:      %s\n", resultFile)
	fmt.Printf("  Порты:       %s\n", portsFile)
	fmt.Printf("  WAF:         out/waf/\n")
	fmt.Printf("  Wappalyzer:  %s\n", wappalyzerFile)
	fmt.Printf("  Отчёт:       %s\n", reportFile)
}
