package proxy

import (
	"bufio"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	proxies []string
	mu      sync.Mutex
	idx     int
)

// Load reads proxy addresses from the given file and shuffles them.
func Load(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var list []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			list = append(list, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	proxies = list
	rand.Seed(time.Now().UnixNano())
	if len(proxies) > 1 {
		rand.Shuffle(len(proxies), func(i, j int) { proxies[i], proxies[j] = proxies[j], proxies[i] })
	}
	idx = 0
	return nil
}

// Count returns the number of loaded proxies.
func Count() int {
	mu.Lock()
	defer mu.Unlock()
	return len(proxies)
}

func next() string {
	mu.Lock()
	defer mu.Unlock()
	if len(proxies) == 0 {
		return ""
	}
	p := proxies[idx]
	idx++
	if idx >= len(proxies) {
		idx = 0
		if len(proxies) > 1 {
			rand.Shuffle(len(proxies), func(i, j int) { proxies[i], proxies[j] = proxies[j], proxies[i] })
		}
	}
	return p
}

// GetProxyURL returns the URL of the next proxy to use.
func GetProxyURL() *url.URL {
	p := next()
	if p == "" {
		return nil
	}
	if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") {
		p = "http://" + p
	}
	u, err := url.Parse(p)
	if err != nil {
		return nil
	}
	return u
}

// NewClient creates an HTTP client that uses the next proxy.
func NewClient(timeout time.Duration) *http.Client {
	proxyURL := GetProxyURL()
	tr := &http.Transport{}
	if proxyURL != nil {
		tr.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}
