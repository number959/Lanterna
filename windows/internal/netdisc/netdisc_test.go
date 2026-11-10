package netdisc

import (
	"net"
	"reflect"
	"testing"
)

func rr(dest string, prefix int, nh string, proto, origin uint32) rawRoute {
	return rawRoute{dest: net.ParseIP(dest), prefix: prefix, nextHop: net.ParseIP(nh), metric: 25, proto: proto, origin: origin}
}

func TestFilterRoutes(t *testing.T) {
	rows := []rawRoute{
		rr("0.0.0.0", 0, "10.20.30.1", protoNetMgmt, 0),       // predefinita
		rr("10.20.30.0", 24, "0.0.0.0", protoLocal, 0),        // rete del PC
		rr("10.20.30.57", 32, "0.0.0.0", protoLocal, 0),       // indirizzo del PC
		rr("10.20.30.255", 32, "0.0.0.0", protoLocal, 0),      // broadcast
		rr("224.0.0.0", 4, "0.0.0.0", protoLocal, 0),          // multicast
		rr("127.0.0.0", 8, "0.0.0.0", protoLocal, 0),          // loopback
		rr("169.254.0.0", 16, "0.0.0.0", protoLocal, 0),       // automatici
		rr("10.20.50.0", 24, "10.20.30.1", protoNetMgmt, 2),   // dal DHCP (opzione 121)
		rr("10.20.50.7", 24, "10.20.30.1", protoNetMgmt, 2),   // stessa rete, indirizzo non allineato
		rr("172.16.0.0", 12, "10.20.30.254", protoNetMgmt, 0), // statica
		rr("93.184.216.0", 24, "10.20.30.1", protoNetMgmt, 0), // pubblica: esclusa
		rr("192.168.100.0", 24, "10.20.30.1", protoDHCP, 0),   // protocollo DHCP
		rr("10.99.0.0", 16, "10.20.30.1", 99, 0),              // origine sconosciuta
	}
	got := filterRoutes(rows)
	want := []Route{
		{Prefix: "10.20.30.0/24", Metric: 25, Origin: "rete collegata"},
		{Prefix: "10.20.50.0/24", NextHop: "10.20.30.1", Metric: 25, Origin: "dhcp"},
		{Prefix: "10.99.0.0/16", NextHop: "10.20.30.1", Metric: 25, Origin: "altro"},
		{Prefix: "172.16.0.0/12", NextHop: "10.20.30.254", Metric: 25, Origin: "manuale"},
		{Prefix: "192.168.100.0/24", NextHop: "10.20.30.1", Metric: 25, Origin: "dhcp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rotte:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseADOutput(t *testing.T) {
	out := "S\t10.20.30.0/24\tSede-Milano\r\nS\t10.20.50.0/24\tSede-Milano\nS\t10.20.30.0/24\tdoppione\nS\tnon-una-rete\tX\nS\t2001:db8::/48\tSede-Milano\nS\t10.10.10.0/24\t\x07Data\x01center\n"
	got := parseADOutput(out)
	want := ADSubnets{Read: "ok", Subnets: []ADSubnet{
		{Prefix: "10.10.10.0/24", Site: "Datacenter"},
		{Prefix: "10.20.30.0/24", Site: "Sede-Milano"},
		{Prefix: "10.20.50.0/24", Site: "Sede-Milano"},
		{Prefix: "2001:db8::/48", Site: "Sede-Milano"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sottoreti:\n got %+v\nwant %+v", got, want)
	}
	if r := parseADOutput("NODOMAIN\n"); r.Read != "nodomain" {
		t.Errorf("fuori dominio: %+v", r)
	}
	if r := parseADOutput("ERR\t-2147016646\n"); r.Read != "unreachable" || r.Error == "" {
		t.Errorf("controller irraggiungibile: %+v", r)
	}
	if r := parseADOutput("ERR\t-2147024891\n"); r.Read != "denied" {
		t.Errorf("accesso negato: %+v", r)
	}
	if r := parseADOutput("ERR\t123\n"); r.Read != "error" {
		t.Errorf("errore generico: %+v", r)
	}
	if r := parseADOutput(""); r.Read != "ok" || len(r.Subnets) != 0 {
		t.Errorf("nessuna sottorete: %+v", r)
	}
}
