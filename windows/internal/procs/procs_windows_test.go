//go:build windows

package procs

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"lanterna/internal/pcinfo"
	"lanterna/internal/sign"
)

// Prova su Windows vero (passo della CI «Prove native dell'agente su
// Windows reale»): processi, firme, servizi, connessioni del processo della
// prova stessa, e nessun indirizzo o profilo nel JSON.
func TestReadWindows(t *testing.T) {
	// Porte e connessioni note di questo processo: devono comparire riassunte.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
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
			defer c.Close()
		}
	}()
	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	udp, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	lport := uint16(ln.Addr().(*net.TCPAddr).Port)
	uport := uint16(udp.LocalAddr().(*net.UDPAddr).Port)

	self := uint32(os.Getpid())
	start := time.Now()
	// La misura del carico «comincia» adesso: questo processo è nato prima e
	// riceve il suo carico.
	d, err := Read(context.Background(), map[uint32]float64{self: 1.5}, time.Now())
	if err != nil || d == nil {
		t.Fatalf("lettura: %v", err)
	}
	t.Logf("%d processi, %d non leggibili, parziale %v, connessioni %v, amministratore %v, in %v", len(d.Items), d.Unreadable, d.Partial, d.ConnsRead, d.Elevated, time.Since(start))
	if len(d.Items) < 20 {
		t.Fatalf("troppo pochi processi: %d", len(d.Items))
	}
	if !d.ConnsRead {
		t.Error("tabelle delle connessioni non lette")
	}
	// Una seconda lettura usa la cache delle firme ed è più rapida.
	start = time.Now()
	if d2, err := Read(context.Background(), map[uint32]float64{self: 1.5}, time.Now().Add(-time.Hour)); err != nil || len(d2.Items) < 20 {
		t.Errorf("seconda lettura: %v", err)
	} else {
		// Una misura cominciata prima che il processo nascesse non è sua.
		for _, it := range d2.Items {
			if it.PID == self && it.CPUPct != nil {
				t.Errorf("carico di un processo nato dopo l'inizio della misura: %v", *it.CPUPct)
			}
		}
	}
	t.Logf("seconda lettura in %v", time.Since(start))
	if d3, err := Read(context.Background(), nil, time.Time{}); err != nil || len(d3.Items) < 20 {
		t.Errorf("terza lettura, senza carichi: %v", err)
	}

	me, system := -1, -1
	ms, svc := 0, 0
	for i, it := range d.Items {
		switch it.PID {
		case self:
			me = i
		case 4:
			system = i
		}
		if n := strings.ToLower(it.Name); (n == "explorer.exe" || n == "svchost.exe") && it.File != nil && sign.IsMicrosoft(it.File.Signature) {
			ms++
		}
		if strings.EqualFold(it.Name, "svchost.exe") && len(it.Services) > 0 {
			svc++
		}
		if it.Polaris && it.PID != self {
			t.Logf("figlio di Polaris: %d %s", it.PID, it.Name)
		}
	}
	if ms == 0 {
		t.Error("nessun explorer.exe o svchost.exe con firma valida di Microsoft")
	}
	if svc == 0 {
		t.Error("nessun servizio associato a svchost.exe")
	}
	if system < 0 || d.Items[system].Name != "System" || d.Items[system].File != nil {
		t.Errorf("processo System non trovato o con un file")
	} else {
		t.Logf("System: in ascolto %+v", d.Items[system].Listen)
	}
	if me < 0 {
		t.Fatal("il processo della prova non è nell'elenco")
	}
	p := d.Items[me]
	t.Logf("questo processo: %+v", p)
	if !p.Polaris || p.Owner != "self" || p.Access != "" || p.CPUPct == nil || *p.CPUPct != 1.5 || p.Started == "" || p.Arch == "" || p.MemoryMB <= 0 {
		t.Errorf("processo della prova: %+v", p)
	}
	if p.File == nil || p.File.Signature == nil || p.File.Signature.Status != "unsigned" {
		t.Errorf("l'eseguibile della prova non è firmato: %+v", p.File)
	} else {
		t.Logf("file della prova: %+v; firma %+v", p.File, p.File.Signature)
	}
	hasTCP, hasUDP := false, false
	for _, l := range p.Listen {
		hasTCP = hasTCP || (l.Proto == "tcp" && l.Port == lport && l.Scope == "local" && !l.IPv6)
		hasUDP = hasUDP || (l.Proto == "udp" && l.Port == uport && l.Scope == "all")
	}
	if !hasTCP || !hasUDP || p.Conns == nil || p.Conns.Local < 2 {
		t.Errorf("porte e connessioni della prova (tcp %d, udp %d): %+v %+v", lport, uport, p.Listen, p.Conns)
	}

	// Nessun indirizzo IP e nessun profilo nel JSON. Per le espressioni
	// regolari si tolgono versioni, descrizioni e percorsi dei file: «1.2.3.4»
	// è spesso una versione, anche dentro un percorso (EdgeUpdate\1.3.195.39).
	// Gli indirizzi remoti veri si cercano invece in tutto il JSON.
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	raw := regexp.MustCompile(`"(version|description|company|path)":"(\\.|[^"\\])*"`).ReplaceAllString(string(b), "")
	if m := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`).FindString(raw); m != "" {
		t.Errorf("indirizzo IPv4 nel JSON: %s", m)
	}
	// IPv6: otto gruppi oppure «::», per non confondere gli orari (10:30:45).
	if m := regexp.MustCompile(`(?i)\b[0-9a-f]{1,4}(:[0-9a-f]{1,4}){7}\b|[0-9a-f]{0,4}::[0-9a-f]{0,4}`).FindString(raw); m != "" {
		t.Errorf("indirizzo IPv6 nel JSON: %s", m)
	}
	socks, _ := sockets()
	for _, r := range socks {
		if !r.remote.IsValid() || r.remote.IsUnspecified() || r.remote.IsLoopback() {
			continue
		}
		// Gli indirizzi pubblici in tutto il JSON, quelli della rete locale
		// (che somigliano di più a una versione, come 10.0.0.1) senza i file.
		ip := r.remote.String()
		if strings.Contains(raw, ip) || (destination(r.remote, r.local) == "internet" && strings.Contains(string(b), ip)) {
			t.Errorf("indirizzo remoto %s nel JSON", ip)
		}
	}
	if prof := os.Getenv("USERPROFILE"); prof != "" {
		q, _ := json.Marshal(prof)
		if strings.Contains(strings.ToLower(string(b)), strings.ToLower(strings.Trim(string(q), `"`))) {
			t.Errorf("profilo dell'utente nel JSON")
		}
	}
	// Il nome dell'account come parola intera (cartelle reindirizzate, nomi
	// dei file) e i SID non escono.
	if u := os.Getenv("USERNAME"); len([]rune(u)) >= 3 && !pcinfo.CommonWords[strings.ToLower(u)] {
		if regexp.MustCompile(`(?i)(^|[^\pL\pN])` + regexp.QuoteMeta(u) + `($|[^\pL\pN])`).Match(b) {
			t.Errorf("nome dell'utente nel JSON")
		}
	}
	if m := regexp.MustCompile(`(?i)S-1-(5-21|12-1)(-\d+){4}`).Find(b); m != nil {
		t.Errorf("SID nel JSON: %s", m)
	}
}
