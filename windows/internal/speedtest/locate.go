package speedtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"lanterna/internal/scan"
)

// target è un server indicato da Locate, con gli indirizzi (e i gettoni di
// accesso, validi un minuto) per il download e l'upload cifrati.
type target struct {
	server   scan.SpeedServer
	download string
	upload   string
}

// locateReply è la risposta di Locate v2 (github.com/m-lab/locate, api/v2):
// solo i campi che servono.
type locateReply struct {
	Results []struct {
		Machine  string `json:"machine"`
		Hostname string `json:"hostname"`
		Location *struct {
			City    string `json:"city"`
			Country string `json:"country"`
		} `json:"location"`
		URLs map[string]string `json:"urls"`
	} `json:"results"`
}

const (
	keyDownload = "wss:///ndt/v7/download"
	keyUpload   = "wss:///ndt/v7/upload"
)

// locate chiede a M-Lab i server vicini: fino a quattro, nell'ordine
// suggerito. 204 (nessuna capacità) e 429 (troppe richieste) significano
// "M-Lab è occupato"; 407 un proxy con un'autenticazione non gestita.
func (t *tester) locate(ctx context.Context) ([]target, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.opt.LocateURL, nil)
	if err != nil {
		return nil, notReached{errors.New("indirizzo del servizio Locate non valido")}
	}
	req.Header.Set("User-Agent", UserAgent(t.opt.Version))
	req.Header.Set("Accept", "application/json")
	tr := &http.Transport{
		Proxy:                 t.opt.Proxy,
		TLSClientConfig:       t.tlsConfig(),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		if ctx.Err() != nil && errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		if isProxyAuth(err) {
			return nil, ErrProxyAuth
		}
		return nil, notReached{fmt.Errorf("M-Lab non raggiungibile: %s", describe(err))}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusTooManyRequests:
		return nil, ErrBusy
	case resp.StatusCode == http.StatusProxyAuthRequired:
		return nil, ErrProxyAuth
	case resp.StatusCode == http.StatusServiceUnavailable:
		return nil, errors.New("M-Lab non ha trovato server disponibili per la tua rete: riprova più tardi")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("il servizio di M-Lab che sceglie il server ha risposto con l'errore HTTP %d", resp.StatusCode)
	case err != nil:
		return nil, fmt.Errorf("risposta di M-Lab interrotta: %s", describe(err))
	}
	return parseLocate(body)
}

// parseLocate estrae i server con gli indirizzi cifrati di download e
// upload, al massimo quattro.
func parseLocate(body []byte) ([]target, error) {
	var r locateReply
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, errors.New("risposta di M-Lab non valida")
	}
	var out []target
	for _, x := range r.Results {
		dl, ul := x.URLs[keyDownload], x.URLs[keyUpload]
		if !validWSS(dl) || !validWSS(ul) {
			continue
		}
		machine := x.Machine
		if machine == "" {
			machine = x.Hostname
		}
		s := scan.SpeedServer{Machine: machine, Site: siteOf(machine)}
		if x.Location != nil {
			s.City, s.Country = x.Location.City, x.Location.Country
		}
		out = append(out, target{server: s, download: dl, upload: ul})
		if len(out) == maxResults {
			break
		}
	}
	if len(out) == 0 {
		return nil, ErrBusy
	}
	return out, nil
}

func validWSS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "wss" && u.Host != ""
}

// siteOf ricava il sito di M-Lab dal nome del server:
// "mlab1-mil05.mlab-oti.measurement-lab.org" -> "mil05";
// "ndt-cia202870-824e392f.dimensione.autojoin..." -> "cia202870".
func siteOf(machine string) string {
	first, _, _ := strings.Cut(machine, ".")
	parts := strings.Split(first, "-")
	switch {
	case len(parts) == 2 && strings.HasPrefix(parts[0], "mlab"):
		return parts[1]
	case len(parts) >= 3 && parts[0] == "ndt" && strings.HasPrefix(parts[1], "mlab"):
		return parts[2]
	case len(parts) >= 2 && parts[0] == "ndt":
		return parts[1]
	}
	return ""
}
