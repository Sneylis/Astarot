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

	Core "Astarot/core/Analyze"
	"Astarot/core/masscan"
)

// PortInfo — открытый порт с подсказкой по сервису.
type PortInfo struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
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
}

type techRow struct {
	Name       string
	Version    string
	Categories string
}

// Report — корневая структура отчёта.
type Report struct {
	Target    string
	Generated string
	Hosts     []HostReport
	Stats     Stats
}

type Stats struct {
	TotalHosts   int
	HostsWithWAF int
	TotalPorts   int
	UniqueIPs    int
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

	// 4. Строим список хостов
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

		r.Hosts = append(r.Hosts, hr)
	}

	// Сортируем хосты по домену
	sort.Slice(r.Hosts, func(i, j int) bool {
		return r.Hosts[i].Domain < r.Hosts[j].Domain
	})

	r.Stats.TotalHosts = len(r.Hosts)
	r.Stats.UniqueIPs = len(uniqueIPs)

	return r, nil
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

  /* ── Footer ── */
  .footer { text-align: center; padding: 32px; color: #30363d; font-size: 12px; }
</style>
</head>
<body>

<div class="header">
  <div class="logo">&#9654;</div>
  <div>
    <h1>Astarot Recon Report</h1>
    <div class="meta">Target: <strong>{{.Target}}</strong> &nbsp;|&nbsp; Generated: {{.Generated}}</div>
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
</div>
{{end}}
</div>

<div class="footer">Generated by Astarot &mdash; {{.Generated}}</div>
</body>
</html>`
