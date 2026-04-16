package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	Core "github.com/Sneylis/Astarot/core/Analyze"
	cveanalyzer "github.com/Sneylis/Astarot/core/CVE"
	jsanalyzer "github.com/Sneylis/Astarot/core/Js"
	"github.com/Sneylis/Astarot/core/masscan"
)

// PortInfo — открытый порт с подсказкой по сервису.
type PortInfo struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
}

// CVERow is a single CVE finding for the HTML template.
type CVERow struct {
	TechName    string
	Version     string
	CVEID       string
	CVSSScore   float64
	Severity    string
	Published   string
	Description string
	NVDURL      string
}

// JSSecretRow is a single secrets hit for the HTML template.
type JSSecretRow struct {
	Name     string
	Value    string
	Context  string
	Severity string
	JSURL    string
}

// JSFileRow is a condensed JS-file entry for the HTML template.
type JSFileRow struct {
	URL          string
	Path         string
	Source       string
	StatusCode   int
	HasSourceMap bool
	IsVendor     bool
	SecretCount  int
}

// HostReport — агрегированные данные по одному хосту для отчёта.
type HostReport struct {
	URL          string
	Domain       string
	IP           string
	StatusCode   int
	Title        string
	Server       string
	PoweredBy    string
	Ports        []PortInfo
	WAF          string
	WAFDetected  bool
	Technologies []techRow
	HasError     bool
	Error        string
	// JS Analysis
	JSFiles      []JSFileRow
	JSSecrets    []JSSecretRow
	JSEndpoints  []string
	HasJS        bool
	HasSecrets   bool
	HasEndpoints bool
	// CVE Analysis
	CVEFindings  []CVERow
	HasCVE       bool
	CVECritical  int
	CVEHigh      int
}

type techRow struct {
	Name       string
	Version    string
	Categories string
}

// Report — корневая структура отчёта.
type Report struct {
	Target     string
	Generated  string
	Hosts      []HostReport
	Stats      Stats
	ExportURLs []string // all hosts + JS endpoints for Burp import
}

type Stats struct {
	TotalHosts    int
	HostsWithWAF  int
	TotalPorts    int
	UniqueIPs     int
	TotalJS       int
	TotalSecrets  int
	TotalCVE      int
	CVECritical   int
	CVEHigh       int
	TotalEndpoints int
}

// masscan JSON entry
type masscanEntry struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port  int    `json:"port"`
		Proto string `json:"proto"`
	} `json:"ports"`
}

// Build читает все выходные файлы сканирования и строит Report.
func Build(
	target string,
	wappalyzerFile string, // tmp/Wappalyzer.json
	portsFile string,      // tmp/Ports.txt  (masscan JSON)
	wafDir string,         // out/waf/
) (*Report, error) {

	// 1. Читаем Wappalyzer результаты
	wappResults, err := loadWappalyzer(wappalyzerFile)
	if err != nil {
		return nil, fmt.Errorf("wappalyzer results: %w", err)
	}

	// 2. Читаем маппинг IP→хост и порты из masscan
	ipMap := masscan.LoadIPMap(portsFile + masscan.IPMapSuffix)
	hostPorts := loadMasscanPorts(portsFile, ipMap)

	// 3. Читаем WAF результаты (один файл на URL)
	hostWAF := loadWAFResults(wafDir)

	// 4. Читаем JS-анализ и CVE-данные
	jsResultsFile := strings.TrimSuffix(portsFile, "Ports.txt") + "js_results.json"
	jsMap := loadJSResults(jsResultsFile)

	cveResultsFile := strings.TrimSuffix(portsFile, "Ports.txt") + "cve_results.json"
	cveMap := loadCVEResults(cveResultsFile)

	// 5. Строим список хостов
	r := &Report{
		Target:    target,
		Generated: time.Now().Format("2006-01-02 15:04:05"),
	}

	uniqueIPs := make(map[string]struct{})

	for _, w := range wappResults {
		domain := stripScheme(w.URL)
		hr := HostReport{
			URL:        w.URL,
			Domain:     domain,
			StatusCode: w.StatusCode,
			Title:      w.Title,
			Server:     w.Server,
			PoweredBy:  w.PoweredBy,
			HasError:   w.Error != "",
			Error:      w.Error,
		}

		// Порты
		if ports, ok := hostPorts[domain]; ok {
			hr.Ports = ports
			r.Stats.TotalPorts += len(ports)
		}
		// Определяем IP
		for ip, host := range ipMap {
			if host == domain {
				hr.IP = ip
				uniqueIPs[ip] = struct{}{}
				break
			}
		}

		// WAF
		if wafName, ok := hostWAF[w.URL]; ok {
			hr.WAF = wafName
			hr.WAFDetected = wafName != "" && wafName != "None" && wafName != "none"
		} else if wafName, ok := hostWAF[domain]; ok {
			hr.WAF = wafName
			hr.WAFDetected = wafName != "" && wafName != "None"
		}
		if hr.WAFDetected {
			r.Stats.HostsWithWAF++
		}

		// Технологии (сортируем по имени)
		names := make([]string, 0, len(w.Technologies))
		for n := range w.Technologies {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			ti := w.Technologies[name]
			hr.Technologies = append(hr.Technologies, techRow{
				Name:       name,
				Version:    ti.Version,
				Categories: strings.Join(ti.Categories, ", "),
			})
		}

		// JS Analysis — merge by URL and domain
		if jsHost, ok := jsMap[w.URL]; ok {
			mergeJSIntoHost(&hr, jsHost)
		} else if jsHost, ok := jsMap[domain]; ok {
			mergeJSIntoHost(&hr, jsHost)
		}
		if hr.HasJS {
			r.Stats.TotalJS += len(hr.JSFiles)
		}
		r.Stats.TotalSecrets += len(hr.JSSecrets)
		r.Stats.TotalEndpoints += len(hr.JSEndpoints)

		// CVE merge
		if cveHost, ok := cveMap[w.URL]; ok {
			mergeCVEIntoHost(&hr, cveHost)
		} else if cveHost, ok := cveMap[domain]; ok {
			mergeCVEIntoHost(&hr, cveHost)
		}
		r.Stats.TotalCVE += len(hr.CVEFindings)
		r.Stats.CVECritical += hr.CVECritical
		r.Stats.CVEHigh += hr.CVEHigh

		r.Hosts = append(r.Hosts, hr)
	}

	// Сортируем хосты по домену
	sort.Slice(r.Hosts, func(i, j int) bool {
		return r.Hosts[i].Domain < r.Hosts[j].Domain
	})

	r.Stats.TotalHosts = len(r.Hosts)
	r.Stats.UniqueIPs = len(uniqueIPs)

	// Build Burp export list: live hosts + JS file URLs + constructed endpoint URLs
	exportSet := make(map[string]struct{})
	for _, h := range r.Hosts {
		exportSet[h.URL] = struct{}{}
		for _, f := range h.JSFiles {
			if f.URL != "" {
				exportSet[f.URL] = struct{}{}
			}
		}
		base := strings.TrimRight(h.URL, "/")
		for _, ep := range h.JSEndpoints {
			exportSet[base+ep] = struct{}{}
		}
	}
	for u := range exportSet {
		r.ExportURLs = append(r.ExportURLs, u)
	}
	sort.Strings(r.ExportURLs)

	return r, nil
}

// mergeJSIntoHost populates JS-related fields on hr from a jsanalyzer.HostResult.
func mergeJSIntoHost(hr *HostReport, js jsanalyzer.HostResult) {
	secretSeen := make(map[string]struct{})  // key: name+"\x00"+value
	endpointSeen := make(map[string]struct{})

	for _, f := range js.JSFiles {
		// Count only unique secrets for this file's badge
		uniqueForFile := 0
		for _, s := range f.Secrets {
			key := s.Name + "\x00" + s.Value
			if _, dup := secretSeen[key]; dup {
				continue
			}
			secretSeen[key] = struct{}{}
			uniqueForFile++
			hr.JSSecrets = append(hr.JSSecrets, JSSecretRow{
				Name:     s.Name,
				Value:    s.Value,
				Context:  s.Context,
				Severity: s.Severity,
				JSURL:    f.URL,
			})
		}

		hr.JSFiles = append(hr.JSFiles, JSFileRow{
			URL:          f.URL,
			Path:         f.Path,
			Source:       f.Source,
			StatusCode:   f.StatusCode,
			HasSourceMap: f.HasSourceMap,
			IsVendor:     f.IsVendor,
			SecretCount:  uniqueForFile,
		})

		for _, ep := range f.Endpoints {
			if _, ok := endpointSeen[ep]; !ok {
				endpointSeen[ep] = struct{}{}
				hr.JSEndpoints = append(hr.JSEndpoints, ep)
			}
		}
	}

	sort.Strings(hr.JSEndpoints)
	hr.HasJS = len(hr.JSFiles) > 0
	hr.HasSecrets = len(hr.JSSecrets) > 0
	hr.HasEndpoints = len(hr.JSEndpoints) > 0
}

// GenerateHTML рендерит отчёт в HTML-файл.
func GenerateHTML(r *Report, outputFile string) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"statusClass": func(code int) string {
			switch {
			case code >= 200 && code < 300:
				return "status-2xx"
			case code >= 300 && code < 400:
				return "status-3xx"
			case code >= 400:
				return "status-4xx"
			default:
				return "status-unknown"
			}
		},
		"serviceHint": serviceHint,
		"add":      func(a, b int) int { return a + b },
		"gt":       func(a, b int) bool { return a > b },
		"lower":    strings.ToLower,
		"contains": strings.Contains,
		"toJS": func(v any) (template.JS, error) {
			b, err := json.Marshal(v)
			return template.JS(b), err
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("template parse: %w", err)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("create html: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, r)
}

// ─────────────────────────────────────────────
// Вспомогательные функции загрузки данных
// ─────────────────────────────────────────────

func loadWappalyzer(path string) ([]Core.Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var results []Core.Result
	return results, json.Unmarshal(data, &results)
}

func loadMasscanPorts(portsFile string, ipMap map[string]string) map[string][]PortInfo {
	out := make(map[string][]PortInfo)

	data, err := os.ReadFile(portsFile)
	if err != nil {
		return out
	}

	// masscan JSON может начинаться с "," — чистим
	s := strings.TrimSpace(string(data))
	s = strings.TrimPrefix(s, ",")
	if !strings.HasPrefix(s, "[") {
		s = "[" + s + "]"
	}
	// убираем финальную запятую перед ]
	s = strings.ReplaceAll(s, ",\n]", "\n]")
	s = strings.ReplaceAll(s, ",\r\n]", "\r\n]")

	var entries []masscanEntry
	if err := json.Unmarshal([]byte(s), &entries); err != nil {
		return out
	}

	for _, e := range entries {
		hostname, ok := ipMap[e.IP]
		if !ok {
			hostname = e.IP
		}
		for _, p := range e.Ports {
			out[hostname] = append(out[hostname], PortInfo{
				Port:    p.Port,
				Proto:   p.Proto,
				Service: serviceHint(p.Port),
			})
		}
	}
	return out
}

// loadCVEResults reads tmp/cve_results.json and indexes by host URL and bare domain.
func loadCVEResults(path string) map[string]cveanalyzer.HostCVEResult {
	out := make(map[string]cveanalyzer.HostCVEResult)
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var report cveanalyzer.CVEReport
	if err := json.Unmarshal(data, &report); err != nil {
		return out
	}
	for _, r := range report.Hosts {
		out[r.HostURL] = r
		out[stripScheme(r.HostURL)] = r
	}
	return out
}

// mergeCVEIntoHost populates CVE-related fields on hr from cveanalyzer.HostCVEResult.
func mergeCVEIntoHost(hr *HostReport, cve cveanalyzer.HostCVEResult) {
	for _, tc := range cve.Findings {
		for _, entry := range tc.CVEs {
			row := CVERow{
				TechName:    tc.Technology,
				Version:     tc.Version,
				CVEID:       entry.ID,
				CVSSScore:   entry.CVSSScore,
				Severity:    entry.Severity,
				Published:   entry.Published,
				Description: entry.Description,
				NVDURL:      entry.NVDURL,
			}
			hr.CVEFindings = append(hr.CVEFindings, row)
			switch strings.ToUpper(entry.Severity) {
			case "CRITICAL":
				hr.CVECritical++
			case "HIGH":
				hr.CVEHigh++
			}
		}
	}
	// Sort: Critical first, then by CVSS score
	sort.Slice(hr.CVEFindings, func(i, j int) bool {
		si := severityOrder(hr.CVEFindings[i].Severity)
		sj := severityOrder(hr.CVEFindings[j].Severity)
		if si != sj {
			return si < sj
		}
		return hr.CVEFindings[i].CVSSScore > hr.CVEFindings[j].CVSSScore
	})
	hr.HasCVE = len(hr.CVEFindings) > 0
}

func severityOrder(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	default:
		return 4
	}
}

// loadJSResults reads tmp/js_results.json and indexes results by URL and bare domain.
func loadJSResults(path string) map[string]jsanalyzer.HostResult {
	out := make(map[string]jsanalyzer.HostResult)
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var results []jsanalyzer.HostResult
	if err := json.Unmarshal(data, &results); err != nil {
		return out
	}
	for _, r := range results {
		out[r.URL] = r
		out[stripScheme(r.URL)] = r
	}
	return out
}

func loadWAFResults(wafDir string) map[string]string {
	out := make(map[string]string)

	entries, err := os.ReadDir(wafDir)
	if err != nil {
		return out
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(wafDir, e.Name()))
		if err != nil {
			continue
		}

		// wafw00f JSON: [{url, detected, firewall, manufacturer}]
		var results []map[string]interface{}
		if err := json.Unmarshal(data, &results); err != nil {
			continue
		}
		for _, r := range results {
			urlVal, _ := r["url"].(string)
			firewall, _ := r["firewall"].(string)
			if firewall == "" {
				if arr, ok := r["detected"].([]interface{}); ok && len(arr) > 0 {
					firewall, _ = arr[0].(string)
				}
			}
			if urlVal != "" {
				out[urlVal] = firewall
				out[stripScheme(urlVal)] = firewall
			}
		}
	}
	return out
}

func stripScheme(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if i := strings.IndexAny(u, "/?#"); i != -1 {
		u = u[:i]
	}
	return u
}

func serviceHint(port int) string {
	services := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
		53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
		443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
		3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5000: "Dev",
		6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
		9000: "Dev", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return ""
}

// ─────────────────────────────────────────────
// HTML шаблон
// ─────────────────────────────────────────────

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Astarot Report — {{.Target}}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0d1117;
    color: #c9d1d9;
    font-size: 14px;
    line-height: 1.5;
  }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* ── Header ── */
  .header {
    background: #161b22;
    border-bottom: 1px solid #30363d;
    padding: 20px 32px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .header h1 { font-size: 22px; color: #e6edf3; font-weight: 700; }
  .header .meta { color: #8b949e; font-size: 13px; margin-top: 2px; }
  .logo { font-size: 28px; }

  /* ── Stats bar ── */
  .stats {
    display: flex;
    gap: 16px;
    padding: 16px 32px;
    background: #161b22;
    border-bottom: 1px solid #30363d;
    flex-wrap: wrap;
  }
  .stat-card {
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 12px 20px;
    min-width: 120px;
    text-align: center;
  }
  .stat-card .num { font-size: 26px; font-weight: 700; color: #58a6ff; }
  .stat-card .label { font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: .5px; }

  /* ── Main layout ── */
  .container { padding: 24px 32px; max-width: 1400px; margin: 0 auto; }

  /* ── Host card ── */
  .host-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    margin-bottom: 20px;
    overflow: hidden;
    transition: border-color .2s;
  }
  .host-card:hover { border-color: #58a6ff44; }

  .host-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 20px;
    background: #1c2128;
    border-bottom: 1px solid #30363d;
    flex-wrap: wrap;
  }
  .host-url { font-size: 16px; font-weight: 600; color: #e6edf3; }
  .host-ip { font-size: 12px; color: #8b949e; font-family: monospace; }

  .host-body { padding: 16px 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  @media (max-width: 800px) { .host-body { grid-template-columns: 1fr; } }

  /* ── Badges ── */
  .badge {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 500;
    white-space: nowrap;
  }
  .badge-port {
    background: #0d2137;
    color: #79c0ff;
    border: 1px solid #1f6feb55;
    font-family: monospace;
  }
  .badge-tech {
    background: #122d22;
    color: #3fb950;
    border: 1px solid #238636;
  }
  .badge-waf-yes {
    background: #3d1f1f;
    color: #ff7b72;
    border: 1px solid #6e2a2a;
  }
  .badge-waf-no {
    background: #0f2618;
    color: #56d364;
    border: 1px solid #1a4b2c;
  }
  .status-2xx { background:#122d22; color:#3fb950; border:1px solid #238636; }
  .status-3xx { background:#1e2d11; color:#d2a679; border:1px solid #8a6226; }
  .status-4xx { background:#3d1f1f; color:#ff7b72; border:1px solid #6e2a2a; }
  .status-unknown { background:#21262d; color:#8b949e; border:1px solid #30363d; }

  /* ── Section titles ── */
  .section-title {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .6px;
    color: #8b949e;
    margin-bottom: 8px;
    font-weight: 600;
  }

  /* ── Tags wrap ── */
  .tags { display: flex; flex-wrap: wrap; gap: 6px; align-items: flex-start; }

  /* ── Tech table ── */
  .tech-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .tech-table th {
    text-align: left; color: #8b949e; font-weight: 500;
    padding: 4px 8px; border-bottom: 1px solid #30363d;
    font-size: 11px; text-transform: uppercase;
  }
  .tech-table td { padding: 5px 8px; border-bottom: 1px solid #21262d; }
  .tech-table tr:last-child td { border-bottom: none; }
  .tech-name { color: #e6edf3; font-weight: 500; }
  .tech-version { color: #79c0ff; font-family: monospace; font-size: 12px; }
  .tech-cats { color: #8b949e; font-size: 11px; }

  /* ── Error ── */
  .error-row { color: #ff7b72; font-size: 12px; font-style: italic; padding: 8px 0; }

  /* ── Title text ── */
  .page-title { color: #8b949e; font-size: 12px; font-style: italic; }

  /* ── Export button ── */
  .export-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 7px 16px;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: background .15s, border-color .15s;
    white-space: nowrap;
  }
  .export-btn:hover { background: #30363d; border-color: #58a6ff; color: #58a6ff; }
  .export-btn svg { width:14px; height:14px; flex-shrink:0; }

  /* ── Footer ── */
  .footer { text-align: center; padding: 32px; color: #30363d; font-size: 12px; }

  /* ── JS section ── */
  .js-section { padding: 0 20px 16px; border-top: 1px solid #21262d; margin-top: 4px; }
  .js-files-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 12px; }
  .js-files-table th { text-align:left; color:#8b949e; font-weight:500; padding:4px 6px;
    border-bottom:1px solid #30363d; font-size:11px; text-transform:uppercase; }
  .js-files-table td { padding:4px 6px; border-bottom:1px solid #161b22; font-family:monospace; font-size:11px; }
  .js-files-table tr:last-child td { border-bottom:none; }
  .js-url { color:#79c0ff; word-break:break-all; }
  .js-vendor { color:#8b949e; font-style:italic; }
  .js-map { color:#3fb950; }

  /* ── Secrets table ── */
  .secrets-table { width:100%; border-collapse:collapse; font-size:12px; }
  .secrets-table th { text-align:left; color:#8b949e; font-weight:500; padding:4px 8px;
    border-bottom:1px solid #30363d; font-size:11px; text-transform:uppercase; }
  .secrets-table td { padding:5px 8px; border-bottom:1px solid #1c2128; vertical-align:top; }
  .secrets-table tr:last-child td { border-bottom:none; }
  .secret-val { font-family:monospace; font-size:11px; word-break:break-all; color:#e6edf3; }
  .secret-ctx { font-size:10px; color:#8b949e; font-family:monospace; word-break:break-all; margin-top:2px; }
  .secret-src { font-size:10px; color:#58a6ff; font-family:monospace; word-break:break-all; }
  .sev-critical { background:#5a0e0e; color:#ff7b72; border:1px solid #9e3030; }
  .sev-high     { background:#3d1f1f; color:#ff9a72; border:1px solid #6e3a2a; }
  .sev-medium   { background:#2d2200; color:#e3b341; border:1px solid #594400; }
  .sev-low      { background:#0f2618; color:#56d364; border:1px solid #1a4b2c; }
  .sev-info     { background:#11222e; color:#79c0ff; border:1px solid #1f4b6e; }
  .secrets-summary { display:flex; gap:8px; margin-bottom:10px; flex-wrap:wrap; }
  .sev-count { display:inline-flex; align-items:center; gap:4px; padding:3px 10px;
    border-radius:10px; font-size:12px; font-weight:600; }

  /* ── Collapsible details ── */
  details { width: 100%; }
  details summary {
    cursor: pointer;
    user-select: none;
    list-style: none;
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 0 6px;
    color: #8b949e;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .6px;
  }
  details summary::-webkit-details-marker { display: none; }
  details summary::before {
    content: '▶';
    font-size: 9px;
    color: #8b949e;
    transition: transform .15s;
    display: inline-block;
  }
  details[open] summary::before { transform: rotate(90deg); }
  details summary:hover { color: #c9d1d9; }

  /* ── Endpoints section ── */
  .endpoints-grid {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
    padding: 4px 0 8px;
  }
  .ep-badge {
    font-family: monospace;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 4px;
    white-space: nowrap;
    border: 1px solid;
  }
  .ep-api     { background:#0d2137; color:#79c0ff; border-color:#1f6feb55; }
  .ep-graphql { background:#1a0d2e; color:#d2a8ff; border-color:#6e40c9; }
  .ep-auth    { background:#1a0d0d; color:#ff7b72; border-color:#6e2a2a; }
  .ep-admin   { background:#2d1a0d; color:#ffa657; border-color:#6e3a2a; }
  .ep-other   { background:#161b22; color:#8b949e; border-color:#30363d; }

  /* ── CVE section ── */
  .cve-section { padding: 0 20px 16px; border-top: 1px solid #21262d; margin-top: 4px; }
  .cve-table { width:100%; border-collapse:collapse; font-size:12px; }
  .cve-table th { text-align:left; color:#8b949e; font-weight:500; padding:5px 8px;
    border-bottom:1px solid #30363d; font-size:11px; text-transform:uppercase; }
  .cve-table td { padding:5px 8px; border-bottom:1px solid #1c2128; vertical-align:top; }
  .cve-table tr:last-child td { border-bottom:none; }
  .cve-id { font-family:monospace; font-weight:600; white-space:nowrap; }
  .cve-tech { color:#e6edf3; font-weight:500; }
  .cve-ver { color:#79c0ff; font-family:monospace; font-size:11px; }
  .cve-score { font-family:monospace; font-weight:700; }
  .cve-desc { color:#8b949e; font-size:11px; line-height:1.4; }
  .cve-summary { display:flex; gap:8px; margin-bottom:10px; flex-wrap:wrap; }
</style>
</head>
<body>

<div class="header">
  <div class="logo">&#9654;</div>
  <div style="flex:1">
    <h1>Astarot Recon Report</h1>
    <div class="meta">Target: <strong>{{.Target}}</strong> &nbsp;|&nbsp; Generated: {{.Generated}}</div>
  </div>
  <div style="display:flex;gap:8px;flex-shrink:0">
    <button class="export-btn" onclick="exportBurp('txt')" title="One URL per line — paste into Burp Target scope">
      <svg viewBox="0 0 16 16" fill="currentColor"><path d="M2.75 14A1.75 1.75 0 0 1 1 12.25v-2.5a.75.75 0 0 1 1.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 0 0 .25-.25v-2.5a.75.75 0 0 1 1.5 0v2.5A1.75 1.75 0 0 1 13.25 14Z"/><path d="M7.25 7.689V2a.75.75 0 0 1 1.5 0v5.689l1.97-1.97a.749.749 0 1 1 1.06 1.061l-3.25 3.25a.749.749 0 0 1-1.06 0L4.22 6.78a.749.749 0 1 1 1.06-1.061z"/></svg>
      Export to Burp
    </button>
    <button class="export-btn" onclick="exportBurp('json')" title="JSON array — for scripting / API clients">
      <svg viewBox="0 0 16 16" fill="currentColor"><path d="M2.75 14A1.75 1.75 0 0 1 1 12.25v-2.5a.75.75 0 0 1 1.5 0v2.5c0 .138.112.25.25.25h10.5a.25.25 0 0 0 .25-.25v-2.5a.75.75 0 0 1 1.5 0v2.5A1.75 1.75 0 0 1 13.25 14Z"/><path d="M7.25 7.689V2a.75.75 0 0 1 1.5 0v5.689l1.97-1.97a.749.749 0 1 1 1.06 1.061l-3.25 3.25a.749.749 0 0 1-1.06 0L4.22 6.78a.749.749 0 1 1 1.06-1.061z"/></svg>
      Export JSON
    </button>
  </div>
</div>

<div class="stats">
  <div class="stat-card">
    <div class="num">{{.Stats.TotalHosts}}</div>
    <div class="label">Live Hosts</div>
  </div>
  <div class="stat-card">
    <div class="num">{{.Stats.UniqueIPs}}</div>
    <div class="label">Unique IPs</div>
  </div>
  <div class="stat-card">
    <div class="num">{{.Stats.TotalPorts}}</div>
    <div class="label">Open Ports</div>
  </div>
  <div class="stat-card">
    <div class="num">{{.Stats.HostsWithWAF}}</div>
    <div class="label">WAF Detected</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#79c0ff">{{.Stats.TotalJS}}</div>
    <div class="label">JS Files</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:#d2a8ff">{{.Stats.TotalEndpoints}}</div>
    <div class="label">API Endpoints</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:{{if gt .Stats.TotalSecrets 0}}#ff7b72{{else}}#56d364{{end}}">{{.Stats.TotalSecrets}}</div>
    <div class="label">JS Secrets</div>
  </div>
  <div class="stat-card">
    <div class="num" style="color:{{if gt .Stats.CVECritical 0}}#ff7b72{{else if gt .Stats.CVEHigh 0}}#ffa657{{else}}#8b949e{{end}}">{{.Stats.TotalCVE}}</div>
    <div class="label">CVEs Found</div>
  </div>
  {{if gt .Stats.CVECritical 0}}
  <div class="stat-card" style="border-color:#9e3030">
    <div class="num" style="color:#ff7b72">{{.Stats.CVECritical}}</div>
    <div class="label">Critical CVEs</div>
  </div>
  {{end}}
</div>

<div class="container">
{{range .Hosts}}
<div class="host-card">

  <div class="host-header">
    <a class="host-url" href="{{.URL}}" target="_blank">{{.Domain}}</a>
    {{if .IP}}<span class="host-ip">{{.IP}}</span>{{end}}
    {{if .StatusCode}}<span class="badge {{statusClass .StatusCode}}">{{.StatusCode}}</span>{{end}}
    {{if .WAFDetected}}
      <span class="badge badge-waf-yes">&#9632; WAF: {{.WAF}}</span>
    {{else if .WAF}}
      <span class="badge badge-waf-no">&#10003; No WAF</span>
    {{end}}
    {{if .Title}}<span class="page-title">"{{.Title}}"</span>{{end}}
  </div>

  <div class="host-body">

    {{/* Левая колонка — порты и заголовки */}}
    <div>
      {{if .Ports}}
      <div class="section-title">Open Ports</div>
      <div class="tags" style="margin-bottom:14px">
        {{range .Ports}}
        <span class="badge badge-port">{{.Port}}/{{.Proto}}{{if .Service}} · {{.Service}}{{end}}</span>
        {{end}}
      </div>
      {{end}}

      {{if or .Server .PoweredBy}}
      <div class="section-title">Server Headers</div>
      <div class="tags">
        {{if .Server}}<span class="badge badge-tech">Server: {{.Server}}</span>{{end}}
        {{if .PoweredBy}}<span class="badge badge-tech">X-Powered-By: {{.PoweredBy}}</span>{{end}}
      </div>
      {{end}}

      {{if .HasError}}
      <div class="error-row">&#9888; {{.Error}}</div>
      {{end}}
    </div>

    {{/* Правая колонка — технологии */}}
    <div>
      {{if .Technologies}}
      <div class="section-title">Technologies ({{len .Technologies}})</div>
      <table class="tech-table">
        <tr>
          <th>Name</th>
          <th>Version</th>
          <th>Category</th>
        </tr>
        {{range .Technologies}}
        <tr>
          <td class="tech-name">{{.Name}}</td>
          <td class="tech-version">{{if .Version}}{{.Version}}{{else}}—{{end}}</td>
          <td class="tech-cats">{{if .Categories}}{{.Categories}}{{else}}—{{end}}</td>
        </tr>
        {{end}}
      </table>
      {{else if not .HasError}}
      <div class="section-title">Technologies</div>
      <span style="color:#8b949e;font-size:12px">No fingerprints detected</span>
      {{end}}
    </div>

  </div>

  {{/* CVE Findings section */}}
  {{if .HasCVE}}
  <div class="cve-section">
    <div class="section-title" style="margin-top:14px;color:{{if gt .CVECritical 0}}#ff7b72{{else if gt .CVEHigh 0}}#ffa657{{else}}#e3b341{{end}}">
      &#9888; CVE Findings ({{len .CVEFindings}})
    </div>

    {{/* Severity summary */}}
    <div class="cve-summary">
      {{$ccrit := 0}}{{$chigh := 0}}{{$cmed := 0}}{{$clow := 0}}
      {{range .CVEFindings}}
        {{if eq .Severity "CRITICAL"}}{{$ccrit = add $ccrit 1}}{{end}}
        {{if eq .Severity "HIGH"}}{{$chigh = add $chigh 1}}{{end}}
        {{if eq .Severity "MEDIUM"}}{{$cmed = add $cmed 1}}{{end}}
        {{if eq .Severity "LOW"}}{{$clow = add $clow 1}}{{end}}
      {{end}}
      {{if gt $ccrit 0}}<span class="sev-count sev-critical">&#128308; Critical: {{$ccrit}}</span>{{end}}
      {{if gt $chigh 0}}<span class="sev-count sev-high">&#9888; High: {{$chigh}}</span>{{end}}
      {{if gt $cmed 0}}<span class="sev-count sev-medium">&#9675; Medium: {{$cmed}}</span>{{end}}
      {{if gt $clow 0}}<span class="sev-count sev-low">&#10003; Low: {{$clow}}</span>{{end}}
    </div>

    <table class="cve-table">
      <tr>
        <th>CVE ID</th>
        <th>Technology</th>
        <th>Version</th>
        <th>CVSS</th>
        <th>Severity</th>
        <th>Published</th>
        <th>Description</th>
      </tr>
      {{range .CVEFindings}}
      <tr>
        <td><a class="cve-id" href="{{.NVDURL}}" target="_blank" style="color:{{if eq .Severity "CRITICAL"}}#ff7b72{{else if eq .Severity "HIGH"}}#ffa657{{else if eq .Severity "MEDIUM"}}#e3b341{{else}}#56d364{{end}}">{{.CVEID}}</a></td>
        <td class="cve-tech">{{.TechName}}</td>
        <td class="cve-ver">{{if .Version}}{{.Version}}{{else}}—{{end}}</td>
        <td class="cve-score" style="color:{{if eq .Severity "CRITICAL"}}#ff7b72{{else if eq .Severity "HIGH"}}#ffa657{{else if eq .Severity "MEDIUM"}}#e3b341{{else}}#56d364{{end}}">{{printf "%.1f" .CVSSScore}}</td>
        <td><span class="badge sev-{{.Severity | lower}}">{{.Severity}}</span></td>
        <td style="white-space:nowrap;color:#8b949e;font-size:11px">{{.Published}}</td>
        <td class="cve-desc">{{.Description}}</td>
      </tr>
      {{end}}
    </table>
  </div>
  {{end}}

  {{/* JS Analysis section */}}
  {{if .HasJS}}
  <div class="js-section">

    {{/* ── JS Files (collapsible) ── */}}
    <details>
      <summary>JS Files ({{len .JSFiles}}){{if .HasSecrets}}&nbsp;&nbsp;<span style="color:#ff7b72;font-weight:700">&#9888; {{len .JSSecrets}} secret{{if gt (len .JSSecrets) 1}}s{{end}}</span>{{end}}</summary>
      <table class="js-files-table">
        <tr>
          <th>Path / URL</th>
          <th>Source</th>
          <th>Status</th>
          <th>Map</th>
          <th>Secrets</th>
          <th>Type</th>
        </tr>
        {{range .JSFiles}}
        <tr>
          <td><a class="js-url" href="{{.URL}}" target="_blank">{{if .Path}}{{.Path}}{{else}}{{.URL}}{{end}}</a></td>
          <td style="color:#8b949e">{{.Source}}</td>
          <td>{{if .StatusCode}}<span class="badge {{statusClass .StatusCode}}">{{.StatusCode}}</span>{{end}}</td>
          <td>{{if .HasSourceMap}}<span class="js-map">✓ .map</span>{{else}}<span style="color:#30363d">—</span>{{end}}</td>
          <td>{{if gt .SecretCount 0}}<span style="color:#ff7b72;font-weight:600">{{.SecretCount}}</span>{{else}}<span style="color:#30363d">0</span>{{end}}</td>
          <td>{{if .IsVendor}}<span class="js-vendor">vendor</span>{{else}}<span style="color:#3fb950">custom</span>{{end}}</td>
        </tr>
        {{end}}
      </table>
    </details>

    {{/* ── API Endpoints (collapsible) ── */}}
    {{if .HasEndpoints}}
    <details>
      <summary>API Endpoints ({{len .JSEndpoints}})</summary>
      <div class="endpoints-grid">
        {{range .JSEndpoints}}
        <span class="ep-badge {{if or (contains . "/auth") (contains . "/login") (contains . "/logout") (contains . "/token") (contains . "/oauth") (contains . "/password")}}ep-auth{{else if or (contains . "/admin") (contains . "/dashboard") (contains . "/manage")}}ep-admin{{else if or (contains . "/graphql") (contains . "/mutation") (contains . "/__typename")}}ep-graphql{{else if or (contains . "/api") (contains . "/v1") (contains . "/v2") (contains . "/v3") (contains . "/rest")}}ep-api{{else}}ep-other{{end}}">{{.}}</span>
        {{end}}
      </div>
    </details>
    {{end}}

    {{/* ── Secrets (always visible when present — high priority) ── */}}
    {{if .HasSecrets}}
    <div class="section-title" style="margin-top:14px;color:#ff7b72">
      &#9888; Secrets / Sensitive Data ({{len .JSSecrets}})
    </div>

    <div class="secrets-summary">
      {{$crit := 0}}{{$high := 0}}{{$med := 0}}{{$low := 0}}
      {{range .JSSecrets}}
        {{if eq .Severity "critical"}}{{$crit = add $crit 1}}{{end}}
        {{if eq .Severity "high"}}{{$high = add $high 1}}{{end}}
        {{if eq .Severity "medium"}}{{$med = add $med 1}}{{end}}
        {{if eq .Severity "low"}}{{$low = add $low 1}}{{end}}
      {{end}}
      {{if gt $crit 0}}<span class="sev-count sev-critical">&#128308; Critical: {{$crit}}</span>{{end}}
      {{if gt $high 0}}<span class="sev-count sev-high">&#9888; High: {{$high}}</span>{{end}}
      {{if gt $med 0}}<span class="sev-count sev-medium">&#9675; Medium: {{$med}}</span>{{end}}
      {{if gt $low 0}}<span class="sev-count sev-low">&#10003; Low: {{$low}}</span>{{end}}
    </div>

    <table class="secrets-table">
      <tr>
        <th>Severity</th>
        <th>Pattern</th>
        <th>Value / Context</th>
        <th>Found In</th>
      </tr>
      {{range .JSSecrets}}
      <tr>
        <td><span class="badge sev-{{.Severity}}">{{.Severity}}</span></td>
        <td style="color:#e6edf3;white-space:nowrap">{{.Name}}</td>
        <td>
          <div class="secret-val">{{.Value}}</div>
          {{if .Context}}<div class="secret-ctx">…{{.Context}}…</div>{{end}}
        </td>
        <td><a class="secret-src" href="{{.JSURL}}" target="_blank">{{.JSURL}}</a></td>
      </tr>
      {{end}}
    </table>
    {{end}}

  </div>
  {{end}}

</div>
{{end}}
</div>

<div class="footer">Generated by Astarot &mdash; {{.Generated}}</div>

<script>
const _exportURLs = {{toJS .ExportURLs}};
const _target = {{toJS .Target}};

function exportBurp(fmt) {
  let content, filename, mime;
  if (fmt === 'json') {
    content = JSON.stringify(_exportURLs, null, 2);
    filename = 'burp_targets_' + _target + '.json';
    mime = 'application/json';
  } else {
    content = _exportURLs.join('\n');
    filename = 'burp_targets_' + _target + '.txt';
    mime = 'text/plain';
  }
  const blob = new Blob([content], {type: mime});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}
</script>

</body>
</html>`
