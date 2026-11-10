package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lanterna/internal/l2disc"
	"lanterna/internal/netdisc"
	"lanterna/internal/snmp"
)

func discStatus(t *testing.T, h http.Handler, path string) (discState, string) {
	t.Helper()
	r := do(t, h, "GET", path, nil)
	if r.Code != 200 {
		t.Fatalf("%s: %d", path, r.Code)
	}
	var st discState
	if err := json.Unmarshal(r.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st, r.Body.String()
}

func TestDiscoverL2(t *testing.T) {
	s := newServer()
	h := s.Handler()
	post := func(body string) *httptest.ResponseRecorder {
		return doBody(t, h, "POST", "/api/discover/l2", "application/json", body)
	}
	if r := post(`{}`); r.Code != http.StatusNotImplemented {
		t.Fatalf("non disponibile: %d", r.Code)
	}
	release := make(chan struct{})
	var got time.Duration
	s.ListenL2 = func(ctx context.Context, d time.Duration) l2disc.Discovery {
		got = d
		select {
		case <-release:
		case <-ctx.Done():
			return l2disc.Discovery{Read: l2disc.ReadError, Error: "ascolto interrotto"}
		}
		return l2disc.Discovery{Read: l2disc.ReadOK, Seconds: int(d / time.Second), Frames: 3,
			Lldp: []l2disc.LLDPNeighbor{{ChassisID: "00:11:22:33:44:55", ChassisIDType: "mac", PortID: "Gi1/0/7", PortIDType: "interface-name", TTL: 120, PortVlanID: 20}}}
	}
	for _, body := range []string{`{"seconds":5}`, `{"seconds":181}`} {
		if r := post(body); r.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", body, r.Code)
		}
	}
	if r := doBody(t, h, "POST", "/api/discover/l2", "text/plain", `{}`); r.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("corpo non JSON: %d", r.Code)
	}
	if r := post(`{}`); r.Code != http.StatusAccepted || !strings.Contains(r.Body.String(), `"seconds":61`) {
		t.Fatalf("avvio: %d %s", r.Code, r.Body)
	}
	if r := post(`{}`); r.Code != http.StatusConflict {
		t.Fatalf("doppio ascolto: %d", r.Code)
	}
	if st, _ := discStatus(t, h, "/api/discover/l2"); !st.Running || st.Seconds != 61 || st.StartedAt == "" {
		t.Fatalf("in corso: %+v", st)
	}
	close(release)
	s.WaitDiscover()
	if got != 61*time.Second {
		t.Fatalf("durata: %v", got)
	}
	st, body := discStatus(t, h, "/api/discover/l2")
	if st.Running || st.Error != "" || !strings.Contains(body, `"portVlanId":20`) {
		t.Fatalf("esito: %s", body)
	}
	// Interruzione: l'esito precedente resta finché il nuovo ascolto non finisce.
	release = make(chan struct{})
	if r := post(`{"seconds":30}`); r.Code != http.StatusAccepted {
		t.Fatalf("secondo avvio: %d", r.Code)
	}
	if r := do(t, h, "DELETE", "/api/discover/l2", nil); r.Code != 200 || !strings.Contains(r.Body.String(), `"stopping":true`) {
		t.Fatalf("interruzione: %d %s", r.Code, r.Body)
	}
	s.WaitDiscover()
	if st, body := discStatus(t, h, "/api/discover/l2"); st.Running || st.Error != "ascolto interrotto" || !strings.Contains(body, `"portVlanId":20`) {
		t.Fatalf("dopo l'interruzione resta l'esito precedente con il messaggio: %s", body)
	}
}

func TestDiscoverAD(t *testing.T) {
	s := newServer()
	h := s.Handler()
	if r := doBody(t, h, "POST", "/api/discover/ad", "application/json", `{}`); r.Code != http.StatusNotImplemented {
		t.Fatalf("non disponibile: %d", r.Code)
	}
	s.ADSubnets = func(context.Context) netdisc.ADSubnets {
		return netdisc.ADSubnets{Read: "ok", Subnets: []netdisc.ADSubnet{{Prefix: "10.20.0.0/16", Site: "Sede"}, {Prefix: "10.30.5.0/24", Site: "Filiale"}}}
	}
	if r := doBody(t, h, "POST", "/api/discover/ad", "application/json", `{}`); r.Code != http.StatusAccepted {
		t.Fatalf("avvio: %d %s", r.Code, r.Body)
	}
	s.WaitDiscover()
	st, body := discStatus(t, h, "/api/discover/ad")
	if st.Running || !strings.Contains(body, `"prefix":"10.30.5.0/24"`) || !strings.Contains(body, `"site":"Filiale"`) {
		t.Fatalf("esito: %s", body)
	}
}

func TestDiscoverSNMP(t *testing.T) {
	s := newServer()
	h := s.Handler()
	post := func(body string) *httptest.ResponseRecorder {
		return doBody(t, h, "POST", "/api/discover/snmp", "application/json", body)
	}
	if r := post(`{"target":"10.0.0.2","authorized":true}`); r.Code != http.StatusNotImplemented {
		t.Fatalf("non disponibile: %d", r.Code)
	}
	const secret = "S3greta!Community"
	var gotCreds snmp.Creds
	s.SNMP = func(ctx context.Context, target string, cr snmp.Creds, progress func(string)) (*snmp.Result, error) {
		gotCreds = cr
		progress("VLAN")
		if target == "10.0.0.9" {
			return nil, &snmp.Error{Kind: snmp.KindTimeout, Msg: "nessuna risposta da 10.0.0.9"}
		}
		return &snmp.Result{Target: target, Version: "2c", Vlans: []snmp.Vlan{{ID: 10, Name: "Uffici"}, {ID: 30, Name: "Medicali"}},
			Interfaces: []snmp.Iface{}, LldpNeighbors: []snmp.Neighbor{}, Arp: []snmp.ArpEntry{}, Fdb: []snmp.FdbEntry{}}, nil
	}
	// Senza conferma dell'autorizzazione non parte nulla.
	if r := post(`{"target":"10.0.0.2","creds":{"version":"2c","community":"` + secret + `"}}`); r.Code != http.StatusBadRequest {
		t.Fatalf("senza autorizzazione: %d", r.Code)
	}
	if gotCreds.Community != "" {
		t.Fatal("lettura partita senza autorizzazione")
	}
	if r := post(`{"target":"10.0.0.2","authorized":true,"creds":{"version":"2c","community":"` + secret + `"}}`); r.Code != http.StatusAccepted {
		t.Fatalf("avvio: %d %s", r.Code, r.Body)
	}
	s.WaitDiscover()
	if gotCreds.Community != secret {
		t.Fatalf("credenziali non passate: %#v", gotCreds)
	}
	st, body := discStatus(t, h, "/api/discover/snmp")
	if st.Running || st.Error != "" || !strings.Contains(body, `"name":"Medicali"`) || strings.Contains(body, "defaultCommunity") {
		t.Fatalf("esito: %s", body)
	}
	// La community predefinita si segnala, senza conservarla.
	if r := post(`{"target":"10.0.0.3","authorized":true,"creds":{"version":"2c","community":"public"}}`); r.Code != http.StatusAccepted {
		t.Fatalf("avvio con public: %d", r.Code)
	}
	s.WaitDiscover()
	// Errore: tipo e messaggio, l'esito precedente resta.
	if r := post(`{"target":"10.0.0.9","authorized":true,"creds":{"version":"2c","community":"` + secret + `"}}`); r.Code != http.StatusAccepted {
		t.Fatalf("avvio verso 10.0.0.9: %d", r.Code)
	}
	s.WaitDiscover()
	st, body = discStatus(t, h, "/api/discover/snmp")
	if st.ErrorKind != "timeout" || !strings.Contains(st.Error, "nessuna risposta") {
		t.Fatalf("errore: %s", body)
	}
	if !strings.Contains(body, `"target":"10.0.0.3"`) || !strings.Contains(body, `"defaultCommunity":true`) || !strings.Contains(body, `"target":"10.0.0.2"`) {
		t.Fatalf("esiti conservati: %s", body)
	}
	// Le credenziali non compaiono mai nelle risposte.
	if strings.Contains(body, secret) || strings.Contains(body, `"public"`) {
		t.Fatalf("credenziali nella risposta: %s", body)
	}
	// Una nuova lettura dello stesso dispositivo sostituisce la precedente.
	if r := post(`{"target":"10.0.0.2","authorized":true,"creds":{"version":"2c","community":"` + secret + `"}}`); r.Code != http.StatusAccepted {
		t.Fatalf("rilettura: %d", r.Code)
	}
	s.WaitDiscover()
	r := do(t, h, "GET", "/api/discover/snmp", nil)
	var list struct {
		Results []struct {
			Target string `json:"target"`
		} `json:"results"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Results) != 2 || list.Results[0].Target != "10.0.0.2" || list.Results[1].Target != "10.0.0.3" {
		t.Fatalf("una lettura per dispositivo, la più recente prima: %s", r.Body)
	}
}

func TestDefaultCommunity(t *testing.T) {
	for _, c := range []struct {
		cr   snmp.Creds
		want bool
	}{
		{snmp.Creds{Version: "2c", Community: "public"}, true},
		{snmp.Creds{Version: "", Community: " PRIVATE "}, true},
		{snmp.Creds{Version: "2c", Community: "public2"}, false},
		{snmp.Creds{Version: "3", User: "public"}, false},
	} {
		if got := defaultCommunity(c.cr); got != c.want {
			t.Errorf("%v: %v", c.cr, got)
		}
	}
}
