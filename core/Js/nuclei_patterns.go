package jsanalyzer

// nuclei_patterns.go — secret detection engine
//
// Three tiers of detection:
//   1. namedRules   — high-confidence, named, severity-labelled rules (Critical/High)
//   2. nucleiPats   — 727 Nuclei keyword patterns from JSMiner (Medium)
//   3. entropyCheck — Shannon entropy scan for unlabelled random-looking strings (High)

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
)

// ─── Tier 1: Named high-confidence rules ─────────────────────────────────────

type namedRule struct {
	Name     string
	Re       *regexp.Regexp
	Severity string
}

var namedRules = []namedRule{
	// ── Critical ──
	{SevCritical + ":private_key", regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |)PRIVATE KEY`), SevCritical},
	{SevCritical + ":aws_access_key", regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`), SevCritical},
	{SevCritical + ":aws_secret_key", regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9+/]{40})["']?`), SevCritical},

	// ── High ──
	{"github_pat", regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255}`), SevHigh},
	{"gitlab_token", regexp.MustCompile(`glpat-[a-zA-Z0-9\-_]{20,22}`), SevHigh},
	{"google_api_key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), SevHigh},
	{"stripe_live_key", regexp.MustCompile(`(?:r|s)k_live_[0-9a-zA-Z]{24,}`), SevHigh},
	{"stripe_test_key", regexp.MustCompile(`(?:r|s)k_test_[0-9a-zA-Z]{24,}`), SevHigh},
	{"slack_token", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,48}`), SevHigh},
	{"slack_webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{6,12}/[a-zA-Z0-9\-_]{15,24}`), SevHigh},
	{"jwt_token", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), SevHigh},
	{"grafana_jwt", regexp.MustCompile(`eyJrIjoi[a-zA-Z0-9\-_+/]{50,100}={0,2}`), SevHigh},
	{"grafana_cloud_key", regexp.MustCompile(`glc_[A-Za-z0-9\-_+/]{32,200}={0,2}`), SevHigh},
	{"grafana_service_key", regexp.MustCompile(`glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`), SevHigh},
	{"sendgrid_key", regexp.MustCompile(`SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`), SevHigh},
	{"twilio_sid", regexp.MustCompile(`AC[a-z0-9]{32}`), SevHigh},
	{"firebase_url", regexp.MustCompile(`[a-z0-9\-]+\.firebaseio\.com`), SevHigh},
	{"s3_bucket", regexp.MustCompile(`[a-z0-9\-\.]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com`), SevHigh},
	{"bearer_token", regexp.MustCompile(`[Bb]earer\s+[a-zA-Z0-9\-=._+/\\]{20,500}`), SevHigh},
	{"basic_auth", regexp.MustCompile(`[Bb]asic\s+[A-Za-z0-9+/]{18,}={0,2}`), SevHigh},
	{"authorization_header", regexp.MustCompile(`(?i)["'\[]*[Aa]uthorization["'\]]*\s*[:=]\s*["']?\b(?:[Tt]oken\s+)?[a-zA-Z0-9\-_+/]{20,500}["']?`), SevHigh},
	{"alibaba_key", regexp.MustCompile(`LTAI[A-Za-z\d]{12,30}`), SevHigh},
	{"tencent_key", regexp.MustCompile(`AKID[A-Za-z\d]{13,40}`), SevHigh},
	{"jdcloud_key", regexp.MustCompile(`JDC_[0-9A-Z]{25,40}`), SevHigh},
	{"apidance_key", regexp.MustCompile(`APID[a-zA-Z0-9]{32,42}`), SevHigh},
	{"wechat_appid", regexp.MustCompile(`["'](wx[a-z0-9]{15,18})["']`), SevHigh},
	{"dingtalk_webhook", regexp.MustCompile(`https://oapi\.dingtalk\.com/robot/send\?access_token=[a-z0-9]{50,80}`), SevHigh},
	{"feishu_webhook", regexp.MustCompile(`https://open\.feishu\.cn/open-apis/bot/v2/hook/[a-z0-9\-]{25,50}`), SevHigh},
	{"weixin_webhook", regexp.MustCompile(`https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[a-zA-Z0-9\-]{25,50}`), SevHigh},

	// ── Medium ──
	{"api_key_generic", regexp.MustCompile(`(?i)["']?(api[_\-]?key|apikey)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']`), SevMedium},
	{"secret_key_generic", regexp.MustCompile(`(?i)["']?(secret[_\-]?key|client[_\-]?secret)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{10,})["']`), SevMedium},
	{"access_token_generic", regexp.MustCompile(`(?i)["']?(access[_\-]?token|auth[_\-]?token)["']?\s*[:=]\s*["']([A-Za-z0-9_\-\.]{20,})["']`), SevMedium},
	{"password_inline", regexp.MustCompile(`(?i)["']?password["']?\s*[:=]\s*["']([^"'<>\s]{6,})["']`), SevMedium},
	{"mailgun_key", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), SevMedium},
	{"stripe_publishable", regexp.MustCompile(`pk_(?:live|test)_[0-9a-zA-Z]{24,}`), SevMedium},
	{"mapbox_token", regexp.MustCompile(`pk\.eyJ1IjoiW[A-Za-z0-9\-_]+`), SevMedium},
	{"cloudinary_url", regexp.MustCompile(`cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z]+`), SevMedium},
	{"heroku_api_key", regexp.MustCompile(`(?i)heroku[_\-]?api[_\-]?key["']?\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["']?`), SevMedium},
	{"discord_token", regexp.MustCompile(`(?i)discord[_\-]?(?:token|bot[_\-]?token)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{59,})["']?`), SevMedium},
	{"npm_token", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), SevMedium},
	{"datadog_key", regexp.MustCompile(`(?i)datadog[_\-]?(?:api[_\-]?)?key["']?\s*[:=]\s*["']?([a-f0-9]{32})["']?`), SevMedium},
	{"azure_storage", regexp.MustCompile(`DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88}==`), SevMedium},
	{"gcp_service_account", regexp.MustCompile(`"type"\s*:\s*"service_account"`)  , SevMedium},
}

// ─── Tier 2: Nuclei patterns (727 from JSMiner) ──────────────────────────────
// All assigned severity = Medium. Values are raw regex strings, compiled once.

var nucleiPatStrings = []string{
	`["']?zopim[_-]?account[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?zendesk[_-]?travis[_-]?github["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?yt[_-]?server[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?yt[_-]?partner[_-]?refresh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?yt[_-]?partner[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?yt[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?yt[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?yt[_-]?account[_-]?refresh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?yt[_-]?account[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?wakatime[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?vscetoken["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?visual[_-]?recognition[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?virustotal[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?vip[_-]?github[_-]?deploy[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?v[_-]?sfdc[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?v[_-]?sfdc[_-]?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?user[_-]?assets[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?user[_-]?assets[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?urban[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?urban[_-]?master[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?urban[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?unity[_-]?serial["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?unity[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?twitteroauthaccesstoken["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?twitteroauthaccesssecret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?twitter[_-]?consumer[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?twitter[_-]?consumer[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?twilio[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?twilio[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?twilio[_-]?configuration[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?twilio[_-]?api[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?twilio[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?travis[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?travis[_-]?gh[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?travis[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?travis[_-]?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?snyk[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?snyk[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?sonar[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?sonar[_-]?organization[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?slack[_-]?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?slack[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?slack[_-]?webhook["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?sentry[_-]?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?sentry[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?sentry[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?sendgrid[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?sendgrid[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?sauce[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?s3[_-]?user[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?s3[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?s3[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?s3[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?rubygems[_-]?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?route53[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?rest[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?release[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?pypi[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?pypi[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?prefect[_-]?cloud[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?pagerduty[_-]?apikey["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?ossrh[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?ossrh[_-]?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?openssl[_-]?key[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?okta[_-]?client[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?octest[_-]?app[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?octest[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?nuget[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?node[_-]?pre[_-]?gyp[_-]?github[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?nexuspassword["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?nexus[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?my[_-]?secret[_-]?env["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?mysql[_-]?root[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?mysql[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?myclient[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?mongo[_-]??url["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?microsoft[_-]?app[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?mailchimp[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?mailchimp[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?leancloud[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?leancloud[_-]?app[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?keystore[_-]?pass["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?key[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?jwt[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?github[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?github[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?firebase[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?firebase[_-]?api[_-]?json["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?faunadb[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?faunadb[_-]?server[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?expo[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?encryption[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?docker[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?dockerhub[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?db[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?database[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?cypress[_-]?record[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?consumer[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?consumer[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?conn[_-]?string["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?connection[_-]?string["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?codeclimate[_-]?repo[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?codecov[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?client[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?cloudinary[_-]?api[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?cloudinary[_-]?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?bundle[_-]?enterprise[_-]?name["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?aws[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?aws[_-]?session[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?aws[_-]?secret[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?aws[_-]?secret[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?aws[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?aws[_-]?account[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?aws[_-]?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?aws[_-]?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?auth[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?artifactory[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?app[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?app[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?apple[_-]?id[_-]?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?apns[_-]?auth[_-]?key[_-]?path["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?api[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?api[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?api[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?account[_-]?sid["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?access[_-]?token[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?access[_-]?token["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?access[_-]?key[_-]?secret["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?access[_-]?key[_-]?id["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?access[_-]?key["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?[-]+BEGIN \w+ PRIVATE KEY[-]+`,
	`["']?private[_-]?key[_-]?(id)?["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?password["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?username["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?[\w_-]*?password[\w_-]*?["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?[\w_-]*?username[\w_-]*?["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?[\w_-]*?accesskey[\w_-]*?["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?[\w_-]*?secret[\w_-]*?["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?[\w_-]*?token[\w_-]*?["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
	`["']?huawei\.oss\.(ak|sk|bucket\.name|endpoint|local\.path)["']?[^\S\r\n]*[=:][^\S\r\n]*["']?[\w-]+["']?`,
}

// Compiled nuclei rules (initialised once in init)
var nucleiRules []namedRule

func init() {
	for i, pat := range nucleiPatStrings {
		r, err := regexp.Compile(pat)
		if err != nil {
			continue // skip malformed pattern
		}
		nucleiRules = append(nucleiRules, namedRule{
			Name:     fmt.Sprintf("nuclei_%d", i),
			Re:       r,
			Severity: SevMedium,
		})
	}
}


// ─── Tier 3: Shannon entropy scanner ─────────────────────────────────────────

// reEntropyCandidate matches long alphanumeric/base64 strings.
// We then check their entropy to filter out URL slugs etc.
var reEntropyCandidate = regexp.MustCompile(`["'` + "`" + `]([A-Za-z0-9+/=_\-]{20,120})["'` + "`" + `]`)

const entropyThreshold = 4.2 // bits per character (random base64 ≈ 6.0)

// shannonEntropy calculates the Shannon entropy of s in bits/char.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64, 64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, cnt := range freq {
		p := cnt / n
		h -= p * math.Log2(p)
	}
	return h
}

// looksLikeFalsePositive returns true for common high-entropy false-positives:
// CSS colour hashes, HTML entities, long URLs, minified CSS selectors, etc.
func looksLikeFalsePositive(s string) bool {
	lower := strings.ToLower(s)
	// CSS hex colours (#rrggbb expanded to 20+ chars in some minifiers)
	if len(s) <= 32 && regexp.MustCompile(`^[0-9a-f]+$`).MatchString(lower) {
		return true
	}
	// Looks like a path / URL fragment
	if strings.Contains(s, "/") || strings.Contains(s, ".") {
		return true
	}
	// All uppercase → likely a constant name, not a secret value
	allUpper := true
	for _, c := range s {
		if unicode.IsLower(c) {
			allUpper = false
			break
		}
	}
	if allUpper {
		return true
	}
	return false
}

// ─── Main extraction function ─────────────────────────────────────────────────

// extractSecrets scans body and returns deduplicated SecretMatch results
// from all three tiers: named rules → Nuclei rules → entropy analysis.
func extractSecrets(body []byte) []SecretMatch {
	seen := make(map[string]struct{}, 32)
	var out []SecretMatch

	add := func(name, value, ctx, sev string) {
		// truncate very long values for readability
		displayVal := value
		if len(displayVal) > 120 {
			displayVal = displayVal[:120] + "…"
		}
		key := name + "|" + displayVal
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, SecretMatch{
			Name:     name,
			Value:    displayVal,
			Context:  ctx,
			Severity: sev,
		})
	}

	// Tier 1 — named high-confidence rules
	for _, rule := range namedRules {
		for _, m := range rule.Re.FindAll(body, -1) {
			ctx := extractContext(body, m)
			add(rule.Name, string(m), ctx, rule.Severity)
		}
	}

	// Tier 2 — Nuclei patterns
	for _, rule := range nucleiRules {
		for _, m := range rule.Re.FindAll(body, -1) {
			ctx := extractContext(body, m)
			add(rule.Name, string(m), ctx, rule.Severity)
		}
	}

	// Tier 3 — entropy analysis (only on non-vendor JS)
	for _, m := range reEntropyCandidate.FindAllSubmatch(body, -1) {
		candidate := string(m[1])
		if looksLikeFalsePositive(candidate) {
			continue
		}
		if shannonEntropy(candidate) >= entropyThreshold {
			ctx := extractContext(body, m[0])
			add("high_entropy_string", candidate, ctx, SevHigh)
		}
	}

	return out
}

// extractContext returns up to 80 characters of surrounding text for context.
func extractContext(body, match []byte) string {
	idx := strings.Index(string(body), string(match))
	if idx < 0 {
		return ""
	}
	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + 40
	if end > len(body) {
		end = len(body)
	}
	// Replace newlines/tabs for clean single-line display
	ctx := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, string(body[start:end]))
	return strings.TrimSpace(ctx)
}
