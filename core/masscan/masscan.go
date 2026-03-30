package masscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const defaultPorts = "80,443,8080,8443,8888,22,21,25,3306,3389,5432,6379,27017,9200,11211,1433,5000,9000"

// IPMapFile — путь к файлу маппинга IP→хост, сохраняемому рядом с portsFile.
const IPMapSuffix = ".ipmap.json"

// Scan резолвит хосты из aliveFile в IP, запускает masscan, сохраняет результаты
// в outputFile (формат masscan JSON) и маппинг IP→хост в outputFile+IPMapSuffix.
func Scan(aliveFile, outputFile string) error {
	domains, err := readLines(aliveFile)
	if err != nil {
		return fmt.Errorf("read alive file: %w", err)
	}
	if len(domains) == 0 {
		fmt.Println("[masscan] Нет хостов для сканирования")
		return nil
	}

	// Резолвим домены → IP
	fmt.Printf("[masscan] Резолвинг %d хостов...\n", len(domains))
	ipToHost := make(map[string]string) // ip → hostname (без схемы)

	for _, d := range domains {
		host := stripScheme(d)
		addrs, err := net.LookupHost(host)
		if err != nil {
			continue
		}
		for _, ip := range addrs {
			if net.ParseIP(ip) != nil {
				if _, exists := ipToHost[ip]; !exists {
					ipToHost[ip] = host
				}
			}
		}
	}

	if len(ipToHost) == 0 {
		fmt.Println("[masscan] Не удалось разрезолвить ни одного IP")
		return nil
	}
	fmt.Printf("[masscan] Уникальных IP: %d\n", len(ipToHost))

	// Сохраняем маппинг IP→хост для отчёта
	if err := saveIPMap(outputFile+IPMapSuffix, ipToHost); err != nil {
		fmt.Printf("[masscan] Не удалось сохранить ip_map: %v\n", err)
	}

	// Записываем IP во временный файл для masscan
	tmpFile := outputFile + ".ips.tmp"
	f, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	for ip := range ipToHost {
		f.WriteString(ip + "\n")
	}
	f.Close()
	defer os.Remove(tmpFile)

	// Запускаем masscan
	fmt.Printf("[masscan] Сканирование портов: %s\n", defaultPorts)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	args := []string{
		"-iL", tmpFile,
		"-p", defaultPorts,
		"--rate", "1000",
		"-oJ", outputFile,
	}

	cmd := exec.CommandContext(ctx, "masscan", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("masscan: %v (stderr: %s)", err, strings.TrimSpace(stderr.String()))
	}

	fmt.Printf("[masscan] Готово → %s\n", outputFile)
	return nil
}

// LoadIPMap читает маппинг IP→хост из файла.
func LoadIPMap(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	m := make(map[string]string)
	_ = json.Unmarshal(data, &m)
	return m
}

func saveIPMap(path string, m map[string]string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func stripScheme(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if i := strings.IndexAny(u, "/?#"); i != -1 {
		u = u[:i]
	}
	return u
}
