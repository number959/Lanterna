package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"lanterna/internal/scan"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// routerClient non usa proxy (il router è nella rete locale), segue al
// massimo 3 redirect verso lo stesso host e accetta i certificati
// autofirmati, normali sui pannelli dei router: qui si legge solo
// l'intestazione pubblica, non si invia nessuna credenziale.
func routerClient(host string) *http.Client {
	return &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // solo lettura del titolo del pannello locale
			DialContext:     (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Hostname() != host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// RouterWeb legge intestazione "Server" e titolo della pagina di gestione.
func RouterWeb(ctx context.Context, host string, httpsOpen bool) (*scan.RouterWeb, error) {
	c := routerClient(host)
	w := &scan.RouterWeb{}
	var lastErr error
	for _, scheme := range []string{"http", "https"} {
		if scheme == "https" && !httpsOpen {
			continue
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", scheme+"://"+host+"/", nil)
		req.Header.Set("User-Agent", "STARNET Polaris (diagnostica di rete)")
		resp, err := c.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if scheme == "https" || resp.Request.URL.Scheme == "https" {
			w.HTTPS = true
		}
		if s := resp.Header.Get("Server"); s != "" && w.Server == "" {
			w.Server = s
		}
		if m := titleRe.FindSubmatch(body); m != nil && w.Title == "" {
			w.Title = strings.Join(strings.Fields(html.UnescapeString(string(m[1]))), " ")
			if len(w.Title) > 80 {
				w.Title = w.Title[:80]
			}
		}
	}
	if w.Server == "" && w.Title == "" && !w.HTTPS {
		if lastErr == nil {
			lastErr = errors.New("nessun pannello web raggiungibile")
		}
		return nil, lastErr
	}
	return w, nil
}

// HTTPCheck verifica la navigazione con una richiesta HTTPS reale,
// passando dal proxy come farebbe il browser (vedi HTTPProxy).
func HTTPCheck(ctx context.Context, url string) scan.HTTPCheck {
	r := scan.HTTPCheck{URL: url}
	c := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{Proxy: HTTPProxy}}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "STARNET Polaris (diagnostica di rete)")
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		r.Error = shortErr(err)
		return r
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	r.Status = resp.StatusCode
	r.OK = resp.StatusCode < 400
	r.TimeMs = scan.Ptr(round1(float64(time.Since(start).Microseconds()) / 1000))
	if !r.OK {
		r.Error = resp.Status
	}
	return r
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 120 {
		s = s[i+2:]
	}
	return s
}
