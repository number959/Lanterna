package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"lanterna/internal/scan"
)

// SSDPAddr è l'indirizzo multicast di UPnP; nei test si sostituisce con un
// server locale.
var SSDPAddr = "239.255.255.250:1900"

var searchTargets = []string{
	"upnp:rootdevice",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
	"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
}

func mSearch(st string) []byte {
	return []byte("M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: " + st + "\r\n" +
		"USER-AGENT: Windows/10 UPnP/1.1 STARNET-Polaris/1.0\r\n\r\n")
}

// ParseSSDP legge una risposta SSDP (formato simile a HTTP) e restituisce
// le intestazioni con il nome in maiuscolo.
func ParseSSDP(b []byte) (map[string]string, bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	if !sc.Scan() || !strings.HasPrefix(strings.ToUpper(sc.Text()), "HTTP/1.1 200") {
		return nil, false
	}
	h := map[string]string{}
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, ":"); i > 0 {
			h[strings.ToUpper(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
		}
	}
	return h, h["LOCATION"] != ""
}

type xmlService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

type xmlDevice struct {
	DeviceType   string       `xml:"deviceType"`
	FriendlyName string       `xml:"friendlyName"`
	Manufacturer string       `xml:"manufacturer"`
	ModelName    string       `xml:"modelName"`
	ModelNumber  string       `xml:"modelNumber"`
	Services     []xmlService `xml:"serviceList>service"`
	Devices      []xmlDevice  `xml:"deviceList>device"`
}

type xmlRoot struct {
	URLBase string    `xml:"URLBase"`
	Device  xmlDevice `xml:"device"`
}

// wanService cerca nell'albero il servizio che gestisce la connessione WAN.
func wanService(d xmlDevice) *xmlService {
	for i := range d.Services {
		if strings.Contains(d.Services[i].ServiceType, "WANIPConnection") || strings.Contains(d.Services[i].ServiceType, "WANPPPConnection") {
			return &d.Services[i]
		}
	}
	for _, c := range d.Devices {
		if s := wanService(c); s != nil {
			return s
		}
	}
	return nil
}

// allowLoopback è attivo solo nei test, dove i dispositivi finti
// rispondono su 127.0.0.1.
var allowLoopback = false

// localURL accetta solo URL http verso indirizzi privati della LAN: le
// risposte SSDP possono arrivare da qualunque dispositivo della rete e non
// devono poter far contattare Internet né servizi in ascolto su questo PC.
func localURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return nil, false
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !(ip.IsPrivate() || ip.IsLinkLocalUnicast() || (allowLoopback && ip.IsLoopback())) {
		return nil, false
	}
	return u, true
}

var lanClient = &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}}

func fetchDescription(ctx context.Context, loc *url.URL) (*xmlRoot, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", loc.String(), nil)
	resp, err := lanClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("descrizione: %s", resp.Status)
	}
	var root xmlRoot
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&root); err != nil {
		return nil, err
	}
	return &root, nil
}

// ExternalIP chiede al router l'indirizzo pubblico (azione standard IGD,
// in sola lettura).
func ExternalIP(ctx context.Context, base *url.URL, svc xmlService) (string, error) {
	ctl, err := base.Parse(svc.ControlURL)
	if err != nil {
		return "", err
	}
	if _, ok := localURL(ctl.String()); !ok {
		return "", fmt.Errorf("URL di controllo non locale")
	}
	body := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body><u:GetExternalIPAddress xmlns:u="` + svc.ServiceType + `"/></s:Body></s:Envelope>`
	req, _ := http.NewRequestWithContext(ctx, "POST", ctl.String(), strings.NewReader(body))
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+svc.ServiceType+`#GetExternalIPAddress"`)
	resp, err := lanClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	var env struct {
		IP string `xml:"Body>GetExternalIPAddressResponse>NewExternalIPAddress"`
	}
	if err := xml.Unmarshal(data, &env); err != nil {
		return "", err
	}
	if net.ParseIP(env.IP) == nil {
		return "", fmt.Errorf("risposta senza indirizzo")
	}
	return env.IP, nil
}

// Discover cerca dispositivi UPnP nella rete locale. localIP (facoltativo)
// fissa la scheda da cui inviare la ricerca.
func Discover(ctx context.Context, localIP string, wait time.Duration) (*scan.UpnpData, error) {
	laddr := &net.UDPAddr{}
	if ip := net.ParseIP(localIP); ip != nil {
		laddr.IP = ip
	}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dst, err := net.ResolveUDPAddr("udp4", SSDPAddr)
	if err != nil {
		return nil, err
	}
	for round := 0; round < 2; round++ { // UDP può perdere pacchetti: due invii
		for _, st := range searchTargets {
			if _, err := conn.WriteToUDP(mSearch(st), dst); err != nil && round == 0 {
				return nil, err
			}
		}
	}
	deadline := time.Now().Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetReadDeadline(deadline)
	type hit struct{ loc, server string }
	seen := map[string]hit{}
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // scadenza: fine della raccolta
		}
		if h, ok := ParseSSDP(buf[:n]); ok {
			if _, dup := seen[h["LOCATION"]]; !dup && len(seen) < 16 {
				seen[h["LOCATION"]] = hit{h["LOCATION"], h["SERVER"]}
			}
		}
	}
	data := &scan.UpnpData{Found: len(seen) > 0, Devices: []scan.UpnpDevice{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range seen {
		u, ok := localURL(h.loc)
		if !ok {
			continue
		}
		wg.Add(1)
		go func(h hit, u *url.URL) {
			defer wg.Done()
			root, err := fetchDescription(ctx, u)
			dev := scan.UpnpDevice{Location: h.loc, Server: h.server}
			var ext string
			igd := false
			if err == nil {
				d := root.Device
				dev.FriendlyName, dev.Manufacturer, dev.ModelName, dev.ModelNumber, dev.DeviceType =
					strings.TrimSpace(d.FriendlyName), strings.TrimSpace(d.Manufacturer), strings.TrimSpace(d.ModelName), strings.TrimSpace(d.ModelNumber), d.DeviceType
				if svc := wanService(d); svc != nil {
					igd = true
					base := u
					if b, err := url.Parse(root.URLBase); err == nil && root.URLBase != "" {
						base = b
					}
					ext, _ = ExternalIP(ctx, base, *svc)
				}
				igd = igd || strings.Contains(d.DeviceType, "InternetGatewayDevice")
			}
			mu.Lock()
			defer mu.Unlock()
			data.Devices = append(data.Devices, dev)
			if igd {
				data.IGD = true
				if ext != "" {
					data.ExternalIP = ext
				}
			}
		}(h, u)
	}
	wg.Wait()
	// Ordine stabile: prima i gateway, poi per nome.
	sortDevices(data.Devices)
	return data, nil
}

func sortDevices(ds []scan.UpnpDevice) {
	rank := func(d scan.UpnpDevice) int {
		if strings.Contains(d.DeviceType, "InternetGatewayDevice") {
			return 0
		}
		return 1
	}
	for i := 1; i < len(ds); i++ {
		for j := i; j > 0; j-- {
			a, b := ds[j-1], ds[j]
			if rank(a) > rank(b) || (rank(a) == rank(b) && a.FriendlyName > b.FriendlyName) {
				ds[j-1], ds[j] = b, a
			}
		}
	}
}
