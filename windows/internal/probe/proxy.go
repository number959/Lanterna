package probe

import (
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
)

// HTTPProxy decide il proxy per la verifica HTTPS. Su Windows main lo
// sostituisce con quello delle impostazioni di sistema, se configurato.
var HTTPProxy = http.ProxyFromEnvironment

// EnvProxySet indica se il proxy è impostato con variabili d'ambiente,
// che hanno la precedenza sulle impostazioni di sistema.
func EnvProxySet() bool {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// WinProxy interpreta le impostazioni proxy di Windows (Internet Settings):
// ProxyServer è "host:porta" oppure "http=host:porta;https=host:porta";
// ProxyOverride è un elenco separato da ";" con caratteri jolly e la voce
// speciale "<local>" (nomi senza punto). Restituisce nil se non c'è proxy.
func WinProxy(server, override string) func(*http.Request) (*url.URL, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return nil
	}
	byScheme := map[string]string{}
	if strings.Contains(server, "=") {
		for _, part := range strings.Split(server, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && v != "" {
				byScheme[strings.ToLower(k)] = v
			}
		}
	} else {
		byScheme["http"], byScheme["https"] = server, server
	}
	var bypass []string
	for _, p := range strings.Split(override, ";") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			bypass = append(bypass, p)
		}
	}
	return func(r *http.Request) (*url.URL, error) {
		host := strings.ToLower(r.URL.Hostname())
		for _, p := range bypass {
			if p == "<local>" && !strings.Contains(host, ".") {
				return nil, nil
			}
			if ok, _ := path.Match(p, host); ok {
				return nil, nil
			}
		}
		target := byScheme[r.URL.Scheme]
		if target == "" && r.URL.Scheme == "https" {
			target = byScheme["http"] // spesso un solo proxy dichiarato per http
		}
		if target == "" {
			return nil, nil
		}
		if !strings.Contains(target, "://") {
			target = "http://" + target
		}
		return url.Parse(target)
	}
}
