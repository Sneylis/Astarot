package cveanalyzer

// ─── CVE data types ───────────────────────────────────────────────────────────

// CVEEntry is a single vulnerability record from NVD.
type CVEEntry struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	CVSSScore   float64 `json:"cvss_score,omitempty"`
	Severity    string  `json:"severity"` // CRITICAL | HIGH | MEDIUM | LOW | NONE
	Published   string  `json:"published,omitempty"`
	NVDURL      string  `json:"nvd_url"`
}

// TechCVE holds all CVEs found for one technology.
type TechCVE struct {
	Technology string     `json:"technology"`
	Version    string     `json:"version,omitempty"`
	SearchTerm string     `json:"search_term"`
	CVEs       []CVEEntry `json:"cves,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// HostCVEResult aggregates CVE findings per host.
type HostCVEResult struct {
	HostURL  string    `json:"host_url"`
	Findings []TechCVE `json:"findings,omitempty"`
}

// CVEReport is the root output structure written to tmp/cve_results.json.
type CVEReport struct {
	Timestamp string          `json:"timestamp"`
	Hosts     []HostCVEResult `json:"hosts"`
}

// ─── NVD API 2.0 response shapes ──────────────────────────────────────────────

type nvdResponse struct {
	TotalResults    int              `json:"totalResults"`
	Vulnerabilities []nvdVulnWrapper `json:"vulnerabilities"`
}

type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	V31 []nvdCVSSV3Metric `json:"cvssMetricV31"`
	V30 []nvdCVSSV3Metric `json:"cvssMetricV30"`
	V2  []nvdCVSSV2Metric `json:"cvssMetricV2"`
}

type nvdCVSSV3Metric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdCVSSV2Metric struct {
	CVSSData struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

// ─── Category filters ─────────────────────────────────────────────────────────

// skipCategories - tech categories that rarely produce meaningful CVEs in NVD.
// CVE lookup is skipped for technologies that only belong to these categories.
var skipCategories = map[string]bool{
	"Analytics":           true,
	"Tag managers":        true,
	"Font scripts":        true,
	"Advertising networks": true,
	"Retargeting":         true,
	"Affiliate programs":  true,
	"Live chat":           true,
	"Marketing automation": true,
	"A/B Testing":         true,
	"Comment systems":     true,
	"CDN":                 true,
	"Cookie compliance":   true,
	"Consent management":  true,
	"Heatmaps & Recording": true,
}

// techSearchMap maps Wappalyzer technology names (lowercase) to NVD keyword
// search terms. Keys that are NOT in this map use the raw lowercase tech name.
var techSearchMap = map[string]string{
	"nginx":                  "nginx",
	"apache":                 "apache http server",
	"apache http server":     "apache http server",
	"microsoft iis":          "microsoft iis",
	"iis":                    "microsoft iis",
	"php":                    "php",
	"wordpress":              "wordpress",
	"drupal":                 "drupal",
	"joomla":                 "joomla",
	"jquery":                 "jquery",
	"jquery ui":              "jquery ui",
	"node.js":                "node.js",
	"express":                "expressjs express",
	"laravel":                "laravel",
	"symfony":                "symfony",
	"django":                 "django",
	"ruby on rails":          "ruby on rails",
	"spring":                 "spring framework",
	"struts":                 "apache struts",
	"tomcat":                 "apache tomcat",
	"log4j":                  "apache log4j",
	"mysql":                  "mysql",
	"postgresql":             "postgresql",
	"mongodb":                "mongodb",
	"redis":                  "redis",
	"elasticsearch":          "elasticsearch",
	"openssl":                "openssl",
	"bootstrap":              "twitter bootstrap",
	"angularjs":              "angular.js",
	"react":                  "facebook react",
	"vue.js":                 "vue.js",
	"next.js":                "next.js",
	"nuxt.js":                "nuxt.js",
	"ubuntu":                 "ubuntu linux",
	"debian":                 "debian linux",
	"centos":                 "centos",
	"windows server":         "microsoft windows server",
	"openssh":                "openssh",
	"openresty":              "openresty",
	"litespeed":              "litespeed web server",
	"caddy":                  "caddy",
	"varnish":                "varnish cache",
	"magento":                "magento",
	"shopify":                "shopify",
	"woocommerce":            "woocommerce",
	"typo3":                  "typo3",
	"bitrix":                 "1c-bitrix",
	"1c-bitrix":              "1c-bitrix",
	"grafana":                "grafana labs grafana",
	"kibana":                 "elastic kibana",
	"jenkins":                "jenkins",
	"gitlab":                 "gitlab",
	"confluence":             "atlassian confluence",
	"jira":                   "atlassian jira",
	"moodle":                 "moodle",
	"roundcube":              "roundcube",
	"phpmyadmin":             "phpmyadmin",
	"asp.net":                "microsoft asp.net",
	"asp.net mvc":            "microsoft asp.net",
	"coldfusion":             "adobe coldfusion",
	"websphere":              "ibm websphere",
	"weblogic":               "oracle weblogic server",
	"glassfish":              "oracle glassfish",
	"haproxy":                "haproxy",
	"squid":                  "squid-cache squid",
	"perl":                   "perl",
	"python":                 "python",
	"ruby":                   "ruby-lang ruby",
	"go":                     "golang go",
	"microsoft exchange":     "microsoft exchange server",
	"sharepoint":             "microsoft sharepoint server",
	"outlook web app":        "microsoft exchange server",
	"cpanel":                 "cpanel",
	"plesk":                  "plesk",
	"prestashop":             "prestashop",
	"opencart":               "opencart",
	"oscommerce":             "oscommerce",
	"mediawiki":              "mediawiki",
	"xwiki":                  "xwiki",
	"dokuwiki":               "dokuwiki",
}
