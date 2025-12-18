package core

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ProcessResults объединяет результаты passive и active сканирования,
// удаляет дубликаты и добавляет https:// префикс
func ProcessResults(passiveFile, activeFile, outputFile string) error {
	fmt.Println("\n[*] Обработка результатов...")

	// Используем map для автоматического удаления дубликатов
	uniqueDomains := make(map[string]struct{})

	// Читаем результаты passive сканирования
	if err := readDomainsFromFile(passiveFile, uniqueDomains); err != nil {
		// Если файл не существует, это не критично
		if !os.IsNotExist(err) {
			return fmt.Errorf("ошибка чтения passive результатов: %v", err)
		}
		fmt.Println("[!] Passive результаты не найдены, пропускаем")
	} else {
		fmt.Printf("[+] Загружено passive доменов: %d\n", len(uniqueDomains))
	}

	// Запоминаем количество после passive
	passiveCount := len(uniqueDomains)

	// Читаем результаты active сканирования
	if err := readDomainsFromFile(activeFile, uniqueDomains); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("ошибка чтения active результатов: %v", err)
		}
		fmt.Println("[!] Active результаты не найдены, пропускаем")
	} else {
		activeCount := len(uniqueDomains) - passiveCount
		fmt.Printf("[+] Загружено active доменов: %d\n", activeCount)
	}

	if len(uniqueDomains) == 0 {
		return fmt.Errorf("не найдено доменов для обработки")
	}

	// Преобразуем map в slice для сортировки
	var domains []string
	for domain := range uniqueDomains {
		// Добавляем https:// если его нет
		if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
			domain = "https://" + domain
		}
		domains = append(domains, domain)
	}

	// Сортируем для удобства
	sort.Strings(domains)

	// Записываем в финальный файл
	if err := writeDomainsToFile(outputFile, domains); err != nil {
		return fmt.Errorf("ошибка записи результатов: %v", err)
	}

	fmt.Printf("\n[✓] Обработка завершена!\n")
	fmt.Printf("[✓] Уникальных доменов: %d\n", len(domains))
	fmt.Printf("[✓] Результаты сохранены в: %s\n", outputFile)

	return nil
}

// CleanupTempFiles удаляет временные файлы после обработки
func CleanupTempFiles(files ...string) {
	for _, file := range files {
		if err := os.Remove(file); err != nil {
			if !os.IsNotExist(err) {
				fmt.Printf("[!] Не удалось удалить временный файл %s: %v\n", file, err)
			}
		}
	}
}

// readDomainsFromFile читает домены из файла и добавляет в map
func readDomainsFromFile(filename string, domains map[string]struct{}) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Удаляем http:// или https:// для нормализации
		line = strings.TrimPrefix(line, "https://")
		line = strings.TrimPrefix(line, "http://")

		// Добавляем в map (автоматически удаляются дубликаты)
		domains[line] = struct{}{}
	}

	return scanner.Err()
}

// writeDomainsToFile записывает домены в файл
func writeDomainsToFile(filename string, domains []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, domain := range domains {
		if _, err := writer.WriteString(domain + "\n"); err != nil {
			return err
		}
	}

	return nil
}

// GetStats возвращает статистику по файлу с доменами
func GetStats(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}

	return count, scanner.Err()
}
