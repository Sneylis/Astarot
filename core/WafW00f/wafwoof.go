package core

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// --- ScanWAF (CLI wrapper for wafw00f) ----------------
type Result map[string]any

type Options struct {
	Proxy     string
	FindAll   bool
	Timeout   time.Duration
	UserAgent string
}

func ScanWAF(ctx context.Context, url string, opt Options) ([]Result, []byte, error) {
	args := []string{"-o", "-", "-f", "json"}
	if opt.FindAll {
		args = append(args, "--findall")
	}
	if opt.Proxy != "" {
		args = append(args, "-p", opt.Proxy)
	}
	args = append(args, url)

	tout := opt.Timeout
	if tout <= 0 {
		tout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, tout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "wafw00f", args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb

	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errb.Bytes(), ctx.Err()
		}
		return nil, errb.Bytes(), err
	}

	raw := bytes.TrimSpace(out.Bytes())
	if len(raw) == 0 {
		return nil, errb.Bytes(), fmt.Errorf("empty JSON (stderr: %s)", strings.TrimSpace(errb.String()))
	}

	// Универсальный разбор: объект ИЛИ массив объектов.
	var results []Result
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &results); err != nil {
			return nil, errb.Bytes(), err
		}
	} else {
		var single Result
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, errb.Bytes(), err
		}
		results = []Result{single}
	}
	return results, errb.Bytes(), nil
}

// --- helper: read lines from file ---------------------
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// --- helper: slugify filename from url ----------------
var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

func slugifyURL(u string) string {
	u = strings.ToLower(u)
	// remove proto
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "https://")
	// replace non-alnum with dash
	s := nonAlnum.ReplaceAllString(u, "-")
	s = strings.Trim(s, "-")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// --- main worker pool that reads alive.txt -------------
func Wafw00fMain() {
	// config — подредактируй под себя
	var (
		aliveFile     = "./tmp/alive.txt"
		proxyFile     = "proxies.txt" // опционально; если нет — оставь пустым или не создавай
		outDir        = "out/waf"
		parallelism   = 8
		perTaskTO     = 20 * time.Second
		useFindAll    = true
		proxyRotation = true
	)

	// создаём папку вывода
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "can't create out dir: %v\n", err)
		os.Exit(1)
	}

	// читаем alive.txt
	urls, err := readLines(aliveFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", aliveFile, err)
		os.Exit(1)
	}
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "no URLs found in", aliveFile)
		os.Exit(1)
	}

	// читаем proxies.txt (опционально)
	var proxies []string
	if _, err := os.Stat(proxyFile); err == nil {
		proxies, _ = readLines(proxyFile)
	}
	// если нет прокси — rotation отключится автоматически
	if len(proxies) == 0 {
		proxyRotation = false
	}

	fmt.Printf("Starting wafw00f scans: %d urls, parallel=%d, proxies=%d\n", len(urls), parallelism, len(proxies))

	sem := make(chan struct{}, parallelism)
	wg := sync.WaitGroup{}
	mu := sync.Mutex{} // для безопасного доступа к счетчику прокси
	proxyIdx := 0

	for _, u := range urls {
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()

			// choose proxy (round-robin) if enabled
			var proxy string
			if proxyRotation {
				mu.Lock()
				if len(proxies) > 0 {
					proxy = proxies[proxyIdx%len(proxies)]
					proxyIdx++
				}
				mu.Unlock()
			}

			ctx := context.Background()
			resList, stderr, err := ScanWAF(ctx, url, Options{
				Proxy:   proxy,
				FindAll: useFindAll,
				Timeout: perTaskTO,
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "[wafw00f] %s -> err: %v, stderr: %s\n", url, err, strings.TrimSpace(string(stderr)))
				saveDebug(outDir, url, nil, stderr, err)
				return
			}

			// сохраняем как массив — даже если там один элемент
			data, _ := json.MarshalIndent(resList, "", "  ")
			filename := filepath.Join(outDir, slugifyURL(url)+".json")
			if err := os.WriteFile(filename, data, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "failed save %s: %v\n", filename, err)
				return
			}
			fmt.Printf("[ok] %s -> %s\n", url, filename)
		}(u)
	}

	wg.Wait()
	fmt.Println("Done.")
}

// saveDebug сохраняет stderr + краткий файл ошибки
func saveDebug(outDir, url string, res []byte, stderr []byte, runErr error) {
	base := filepath.Join(outDir, slugifyURL(url))
	if stderr != nil && len(stderr) > 0 {
		_ = os.WriteFile(base+".stderr.txt", stderr, 0o644)
	}
	if runErr != nil {
		_ = os.WriteFile(base+".error.txt", []byte(runErr.Error()), 0o644)
	}
	if res != nil && len(res) > 0 {
		_ = os.WriteFile(base+".raw", res, 0o644)
	}
}
