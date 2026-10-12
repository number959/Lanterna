package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
)

func f(v float64) *float64 { return &v }

func TestPingStats(t *testing.T) {
	st := PingStats("1.1.1.1", "Cloudflare", "icmp", []*float64{f(10), nil, f(14), f(12.04)})
	if st.Sent != 4 || st.Received != 3 || *st.MinMs != 10 || *st.MaxMs != 14 || *st.AvgMs != 12 {
		t.Fatalf("%+v", st)
	}
	// differenze consecutive tra risposte: |14-10| + |12.04-14| = 5.96 / 2 = 2.98
	if *st.JitterMs != 3 || st.Samples[1] != nil || *st.Samples[3] != 12 {
		t.Fatalf("jitter %v campioni %v", *st.JitterMs, st.Samples)
	}
	none := PingStats("x", "", "icmp", []*float64{nil, nil})
	if none.Received != 0 || none.AvgMs != nil {
		t.Fatalf("%+v", none)
	}
}

func TestBuildQueryBytes(t *testing.T) {
	q, err := BuildQuery(0xbeef, "a.it")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 2, 'i', 't', 0, 0, 1, 0, 1}
	if string(q) != string(want) {
		t.Fatalf("% x", q)
	}
	if _, err := BuildQuery(1, "bad..name"); err == nil {
		t.Fatal("nome con etichetta vuota accettato")
	}
}

// fakeDNS risponde alle domande con il codice indicato dopo un ritardo.
func fakeDNS(t *testing.T, rcode byte, delay time.Duration) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := append([]byte(nil), buf[:n]...)
			resp[2] |= 0x80 // QR
			resp[3] = 0x80 | rcode
			time.Sleep(delay)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestQueryAndMeasure(t *testing.T) {
	addr := fakeDNS(t, 0, 5*time.Millisecond)
	host, port, _ := net.SplitHostPort(addr)
	// MeasureServer usa la porta 53: qui si interroga direttamente la porta del server finto.
	d, err := queryAddr(addr, "www.esempio.it")
	if err != nil || d < 5*time.Millisecond {
		t.Fatalf("%v %v", d, err)
	}
	_ = host
	_ = port
	refused := fakeDNS(t, 5, 0)
	if _, err := queryAddr(refused, "x.it"); err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("atteso REFUSED: %v", err)
	}
}

// queryAddr è QueryOnce verso un indirizzo host:porta arbitrario (solo test).
func queryAddr(addr, name string) (time.Duration, error) {
	id := uint16(4242)
	q, _ := BuildQuery(id, name)
	c, err := net.Dial("udp", addr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	start := time.Now()
	_, _ = c.Write(q)
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return 0, err
	}
	return time.Since(start), CheckResponse(buf[:n], id)
}

func TestCheckResponse(t *testing.T) {
	r := make([]byte, 12)
	binary.BigEndian.PutUint16(r, 7)
	if CheckResponse(r, 7) == nil {
		t.Fatal("senza bit QR non è una risposta")
	}
	r[2] = 0x80
	r[3] = 3 // NXDOMAIN: il server ha risposto
	if err := CheckResponse(r, 7); err != nil {
		t.Fatal(err)
	}
	if CheckResponse(r, 8) == nil {
		t.Fatal("ID diverso accettato")
	}
	r[3] = 2
	if err := CheckResponse(r, 7); err == nil || !strings.Contains(err.Error(), "SERVFAIL") {
		t.Fatal(err)
	}
}

func TestMeasureServerTimeout(t *testing.T) {
	// Nessun server in ascolto su un indirizzo di documentazione: errore, non blocco.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	r := MeasureServer(ctx, "192.0.2.1", "test", DNSNames)
	if r.OK || r.Error == "" || time.Since(start) > 3*time.Second {
		t.Fatalf("%+v in %v", r, time.Since(start))
	}
}

func TestParseSSDP(t *testing.T) {
	resp := "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: upnp:rootdevice\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\nSERVER: Linux/3.4 UPnP/1.0 MiniUPnPd/1.9\r\n\r\n"
	h, ok := ParseSSDP([]byte(resp))
	if !ok || h["LOCATION"] != "http://192.168.1.1:5000/rootDesc.xml" || h["SERVER"] != "Linux/3.4 UPnP/1.0 MiniUPnPd/1.9" {
		t.Fatalf("%v %v", h, ok)
	}
	if _, ok := ParseSSDP([]byte("NOTIFY * HTTP/1.1\r\nLOCATION: x\r\n\r\n")); ok {
		t.Fatal("NOTIFY non è una risposta")
	}
}

func TestLocalURL(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://192.168.1.1:5000/d.xml": true,
		"http://10.0.0.1/d.xml":         true,
		"http://169.254.1.1/d.xml":      true,
		"https://192.168.1.1/d.xml":     false,
		"http://8.8.8.8/d.xml":          false,
		"http://127.0.0.1/d.xml":        false,
		"http://router.local/d.xml":     false,
	} {
		if _, ok := localURL(raw); ok != want {
			t.Errorf("%s: %v", raw, ok)
		}
	}
}

const igdDesc = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
 <device>
  <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
  <friendlyName>Router Casa</friendlyName>
  <manufacturer>Demo Networks</manufacturer>
  <modelName>DN-2400</modelName>
  <modelNumber>v2</modelNumber>
  <deviceList><device>
   <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
   <deviceList><device>
    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
    <serviceList><service>
     <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
     <controlURL>/ctl/IPConn</controlURL>
    </service></serviceList>
   </device></deviceList>
  </device></deviceList>
 </device>
</root>`

func TestDiscoverWithFakeRouter(t *testing.T) {
	allowLoopback = true
	defer func() { allowLoopback = false }()

	var soapAction string
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rootDesc.xml":
			fmt.Fprint(w, igdDesc)
		case "/ctl/IPConn":
			soapAction = r.Header.Get("SOAPAction")
			fmt.Fprint(w, `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>`+
				`<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">`+
				`<NewExternalIPAddress>93.40.12.34</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer web.Close()

	// Finto SSDP: risponde a ogni M-SEARCH indicando la descrizione.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if !strings.HasPrefix(string(buf[:n]), "M-SEARCH") {
				continue
			}
			resp := "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nLOCATION: " + web.URL + "/rootDesc.xml\r\nSERVER: MiniUPnPd/1.9\r\n\r\n"
			_, _ = pc.WriteTo([]byte(resp), addr)
		}
	}()
	old := SSDPAddr
	SSDPAddr = pc.LocalAddr().String()
	defer func() { SSDPAddr = old }()

	data, err := Discover(context.Background(), "127.0.0.1", 600*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !data.Found || !data.IGD || data.ExternalIP != "93.40.12.34" || len(data.Devices) != 1 {
		t.Fatalf("%+v", data)
	}
	d := data.Devices[0]
	if d.ModelName != "DN-2400" || d.Manufacturer != "Demo Networks" || d.Server != "MiniUPnPd/1.9" {
		t.Fatalf("%+v", d)
	}
	if soapAction != `"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"` {
		t.Fatalf("SOAPAction = %s", soapAction)
	}
}

func TestCheckPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	open := ln.Addr().(*net.TCPAddr).Port
	closed, _ := net.Listen("tcp", "127.0.0.1:0")
	closedPort := closed.Addr().(*net.TCPAddr).Port
	closed.Close()
	res := CheckPorts(context.Background(), "127.0.0.1", []scan.PortCheck{{Port: open, Service: "a"}, {Port: closedPort, Service: "b"}}, time.Second)
	if !res[0].Open || res[1].Open {
		t.Fatalf("%+v", res)
	}
}

func TestRouterWeb(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "mini_httpd/1.19")
		fmt.Fprint(w, "<html><head><TITLE>\n  DN-2400 &amp; Login </TITLE></head></html>")
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	web, err := RouterWeb(context.Background(), host, false)
	if err != nil {
		t.Fatal(err)
	}
	if web.Server != "mini_httpd/1.19" || web.Title != "DN-2400 & Login" || web.HTTPS {
		t.Fatalf("%+v", web)
	}
}

func TestHTTPCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	r := HTTPCheck(context.Background(), srv.URL+"/generate_204")
	if !r.OK || r.Status != 204 || r.TimeMs == nil {
		t.Fatalf("%+v", r)
	}
	bad := HTTPCheck(context.Background(), "http://127.0.0.1:1/")
	if bad.OK || bad.Error == "" {
		t.Fatalf("%+v", bad)
	}
}
