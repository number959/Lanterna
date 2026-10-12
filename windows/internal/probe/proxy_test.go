package probe

import (
	"net/http"
	"testing"
)

func TestWinProxy(t *testing.T) {
	get := func(server, override, raw string) string {
		f := WinProxy(server, override)
		if f == nil {
			return "nessun proxy"
		}
		req, _ := http.NewRequest("GET", raw, nil)
		u, err := f(req)
		if err != nil {
			t.Fatal(err)
		}
		if u == nil {
			return "diretto"
		}
		return u.String()
	}
	cases := []struct{ server, override, url, want string }{
		{"", "", "https://www.google.com/", "nessun proxy"},
		{"proxy.ufficio.it:8080", "", "https://www.google.com/", "http://proxy.ufficio.it:8080"},
		{"http=p1:3128;https=p2:3129", "", "https://www.google.com/", "http://p2:3129"},
		{"http=p1:3128", "", "https://www.google.com/", "http://p1:3128"},
		{"proxy:8080", "<local>;*.ufficio.it;10.*", "https://intranet/", "diretto"},
		{"proxy:8080", "<local>;*.ufficio.it;10.*", "https://wiki.ufficio.it/", "diretto"},
		{"proxy:8080", "<local>;*.ufficio.it;10.*", "http://10.1.2.3/", "diretto"},
		{"proxy:8080", "<local>;*.ufficio.it", "https://cp.cloudflare.com/generate_204", "http://proxy:8080"},
		{"https=http://p3:443", "", "https://x.it/", "http://p3:443"},
	}
	for _, c := range cases {
		if got := get(c.server, c.override, c.url); got != c.want {
			t.Errorf("%q %q %s: %s, atteso %s", c.server, c.override, c.url, got, c.want)
		}
	}
}
