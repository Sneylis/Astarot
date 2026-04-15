package jsanalyzer


// ─── Output structures ────────────────────────────────────────────────────────

// JSFile represents a single discovered JavaScript file with analysis metadata.
type JSFile struct {
	URL           string        `json:"url"`
	Path          string        `json:"path,omitempty"`
	Source        string        `json:"source"` // passive | html_crawl | brute | recursive
	StatusCode    int           `json:"status_code,omitempty"`
	ContentLength int64         `json:"content_length,omitempty"`
	HasSourceMap  bool          `json:"has_sourcemap,omitempty"`
	IsVendor      bool          `json:"is_vendor,omitempty"`
	Secrets       []SecretMatch `json:"secrets,omitempty"`
	Endpoints     []string      `json:"endpoints,omitempty"`
	JSRefs        []string      `json:"js_refs,omitempty"`
}

// TechInfo mirrors the Wappalyzer output format (reused in report merging).
type TechInfo struct {
	Categories []string `json:"categories,omitempty"`
	Website    string   `json:"website,omitempty"`
}

// HostResult is the complete JS-analysis result for one subdomain.
// JSON shape matches the project's existing Wappalyzer output so the
// HTML report builder can consume both files uniformly.
type HostResult struct {
	URL          string              `json:"url"`
	Timestamp    string              `json:"timestamp"`
	StatusCode   int                 `json:"status_code,omitempty"`
	Title        string              `json:"title,omitempty"`
	Server       string              `json:"server,omitempty"`
	Technologies map[string]TechInfo `json:"technologies,omitempty"`
	JSPaths      []string            `json:"JS_PATH,omitempty"`  // flat list of discovered paths
	JSFiles      []JSFile            `json:"js_files,omitempty"` // detailed per-file analysis
	Error        string              `json:"error,omitempty"`
}

// ─── Constants ────────────────────────────────────────────────────────────────

// defaultUA - standard Chrome User-Agent used for ALL brute-force / crawl
// requests so WAF/rate-limiters see normal browser traffic.
const defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// maxBodyBytes is the per-JS-file download cap (3 MB). Bundles larger than
// this are truncated for analysis but still recorded.
const maxBodyBytes = 3 * 1024 * 1024

// recursionDepth - how many levels of JS→JS references to follow.
const recursionDepth = 2

// ─── Secret severity levels ───────────────────────────────────────────────────

const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"
)

// SecretMatch is a single secrets hit with context.
type SecretMatch struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Context  string `json:"context,omitempty"` // up to 80 chars around the match
	Severity string `json:"severity"`
}

// ─── Vendor library detection ─────────────────────────────────────────────────

// vendorLibPatterns - lowercase substrings in the URL path that indicate
// third-party / library code (not custom application code).
var vendorLibPatterns = []string{
	"jquery", "react.", "react-dom", "angular", "vue.", "lodash.",
	"underscore", "backbone", "bootstrap", "moment.", "axios",
	"polyfill", "modernizr", "three.min", "d3.min", "chart.min",
	"highlight", "prism.", "codemirror", "ace.min", "monaco",
	"socket.io", "swagger-ui", "fontawesome", "material-ui",
	"vendor.", "vendors~", "chunk-vendors", "vendor-chunk",
	"runtime-main",
}

// ─── Framework-specific brute paths ──────────────────────────────────────────

// frameworkBrutePaths maps a detected framework/stack to JS paths worth checking.
// These are relative to the site root (no leading slash needed – added at runtime).
var frameworkBrutePaths = map[string][]string{
	"react": {
		"asset-manifest.json",
		"static/js/main.chunk.js",
		"static/js/bundle.js",
		"static/js/vendors~main.chunk.js",
		"static/js/2.chunk.js",
		"static/js/runtime-main.js",
		"static/js/runtime~main.js",
		"service-worker.js",
		"precache-manifest.js",
	},
	"vue": {
		"manifest.json",
		"js/app.js",
		"js/chunk-vendors.js",
		"js/vendor.js",
		"js/about.js",
	},
	"angular": {
		"main.js", "polyfills.js", "runtime.js",
		"vendor.js", "styles.js",
		"ngsw.json", "ngsw-worker.js",
	},
	"next": {
		"_next/static/chunks/main.js",
		"_next/static/chunks/webpack.js",
		"_next/static/chunks/framework.js",
		"_next/static/chunks/pages/_app.js",
		"_next/static/chunks/pages/index.js",
	},
	"nuxt": {
		"_nuxt/app.js", "_nuxt/vendor.js",
		"_nuxt/manifest.json",
		"_nuxt/pages/index.js",
		"_nuxt/pages/about.js",
	},
	"webpack": {
		"manifest.json", "asset-manifest.json",
		"js/app.js", "js/vendor.js", "js/runtime.js",
		"js/main.js", "js/index.js",
	},
	// default paths tried for every host regardless of detected framework
	"default": {
		"app.js", "main.js", "index.js", "bundle.js", "vendor.js",
		"assets/js/app.js", "assets/js/main.js", "assets/js/index.js",
		"static/js/app.js", "static/app.js",
		"dist/app.js", "dist/main.js", "dist/bundle.js",
		"js/app.js", "js/main.js", "js/bundle.js",
		"public/js/app.js", "build/js/main.js",
	},
}

// sensitiveFilePaths - non-JS files worth checking for information disclosure
var sensitiveFilePaths = []string{
	"package.json",
	".env",
	"webpack.config.js",
	"manifest.json",
	"asset-manifest.json",
	"robots.txt",
	"sitemap.xml",
	"config.js",
	"config.json",
	"settings.js",
	"api.js",
	"server.js",
	"app.js",
}

// versionVariants - when /v1/ is found, try these sibling paths
var versionVariants = []string{"v2", "v3", "dev", "old", "backup", "test", "staging", "beta"}
