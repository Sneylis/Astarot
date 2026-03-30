package core

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	probe "Astarot/core/Checker"
)

// DedupeAndCheckAlive reads raw domains from rawFile, performs HTTP alive checks
// using checker.go, deduplicates results, and writes live URLs to resultFile.
// proxiesFile is optional — if the file doesn't exist, direct connections are used.
func DedupeAndCheckAlive(rawFile, resultFile, proxiesFile string) error {
	fmt.Println("\n[*] Дедупликация и проверка живых хостов...")

	cfg := probe.DefaultAliveConfig()
	ctx := context.Background()

	out := make(chan string, 512)
	errCh := make(chan error, 1)

	go func() {
		errCh <- probe.IS_allive(ctx, rawFile, proxiesFile, out, cfg)
	}()

	// Collect and deduplicate (IS_allive closes out when done)
	seen := make(map[string]struct{})
	var results []string
	for url := range out {
		if _, ok := seen[url]; !ok {
			seen[url] = struct{}{}
			results = append(results, url)
			fmt.Printf("[✓] Живой: %s\n", url)
		}
	}

	if err := <-errCh; err != nil {
		return fmt.Errorf("alive check: %w", err)
	}

	sort.Strings(results)

	if err := writeDomainsToFile(resultFile, results); err != nil {
		return fmt.Errorf("write result: %w", err)
	}

	fmt.Printf("\n[✓] Живых хостов: %d → %s\n", len(results), resultFile)
	return nil
}

// GetStats counts non-empty, non-comment lines in a file.
func GetStats(filename string) (int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count, sc.Err()
}

func writeDomainsToFile(filename string, domains []string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	for _, d := range domains {
		if _, err := w.WriteString(d + "\n"); err != nil {
			return err
		}
	}
	return nil
}
