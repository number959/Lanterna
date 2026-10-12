package probe

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"lanterna/internal/scan"
)

// RouterPorts sono i servizi di gestione più comuni sui router domestici.
// Si controllano esclusivamente sul gateway della rete a cui si è collegati.
var RouterPorts = []scan.PortCheck{
	{Port: 21, Service: "ftp"}, {Port: 22, Service: "ssh"}, {Port: 23, Service: "telnet"},
	{Port: 53, Service: "dns"}, {Port: 80, Service: "http"}, {Port: 139, Service: "netbios"},
	{Port: 443, Service: "https"}, {Port: 445, Service: "smb"}, {Port: 5000, Service: "upnp"},
	{Port: 7547, Service: "tr-069"}, {Port: 8080, Service: "http-alt"}, {Port: 8443, Service: "https-alt"},
	{Port: 49152, Service: "upnp"},
}

// CheckPorts tenta una connessione TCP a ciascuna porta (in parallelo).
func CheckPorts(ctx context.Context, host string, ports []scan.PortCheck, timeout time.Duration) []scan.PortCheck {
	out := make([]scan.PortCheck, len(ports))
	var wg sync.WaitGroup
	for i, p := range ports {
		out[i] = p
		wg.Add(1)
		go func(i int, p scan.PortCheck) {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(p.Port)))
			if err == nil {
				out[i].Open = true
				c.Close()
			}
		}(i, p)
	}
	wg.Wait()
	return out
}
