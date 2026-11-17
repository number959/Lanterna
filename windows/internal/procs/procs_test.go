package procs

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"testing"

	"lanterna/internal/scan"
)

// Righe costruite a mano con gli scostamenti di tcpmib.h e udpmib.h.
func tcp4Table(rows ...[6]uint32) []byte {
	b := make([]byte, 4+len(rows)*tcp4RowSize)
	binary.LittleEndian.PutUint32(b, uint32(len(rows)))
	for i, r := range rows {
		o := b[4+i*tcp4RowSize:]
		binary.LittleEndian.PutUint32(o, r[0])
		binary.BigEndian.PutUint32(o[4:], r[1]) // in_addr: byte nell'ordine di rete
		binary.BigEndian.PutUint16(o[8:], uint16(r[2]))
		binary.BigEndian.PutUint32(o[12:], r[3])
		binary.BigEndian.PutUint16(o[16:], uint16(r[4]))
		binary.LittleEndian.PutUint32(o[20:], r[5])
	}
	return b
}

func ip4(s string) uint32 {
	a := netip.MustParseAddr(s).As4()
	return binary.BigEndian.Uint32(a[:])
}

func TestParseTables(t *testing.T) {
	b := tcp4Table(
		[6]uint32{tcpListen, 0, 445, 0, 0, 4},
		[6]uint32{tcpEstab, ip4("192.168.1.34"), 50123, ip4("140.82.112.3"), 443, 1200},
	)
	rs, err := parseTCP4(b)
	if err != nil || len(rs) != 2 || rs[0].localPort != 445 || rs[0].pid != 4 || rs[0].state != tcpListen || !rs[0].local.IsUnspecified() {
		t.Fatalf("TCP4: %+v %v", rs, err)
	}
	if rs[1].remote.String() != "140.82.112.3" || rs[1].remotePort != 443 || rs[1].localPort != 50123 || rs[1].pid != 1200 || rs[1].v6 {
		t.Fatalf("TCP4 connessione: %+v", rs[1])
	}
	// Tabella troncata: nessuna riga inventata.
	if rs, err := parseTCP4(b[:30]); err == nil || len(rs) != 0 {
		t.Fatalf("troncata: %+v %v", rs, err)
	}
	if _, err := parseTCP4(nil); err == nil {
		t.Fatal("tabella vuota")
	}

	// TCP6: ucLocalAddr @0, porta @20, remoto @24, porta @44, stato @48, PID @52.
	b6 := make([]byte, 4+tcp6RowSize)
	binary.LittleEndian.PutUint32(b6, 1)
	r := b6[4:]
	copy(r, netip.MustParseAddr("::1").AsSlice())
	binary.BigEndian.PutUint16(r[20:], 8737)
	copy(r[24:], netip.MustParseAddr("::ffff:10.0.0.7").AsSlice())
	binary.BigEndian.PutUint16(r[44:], 50000)
	binary.LittleEndian.PutUint32(r[48:], tcpEstab)
	binary.LittleEndian.PutUint32(r[52:], 77)
	rs6, err := parseTCP6(b6)
	if err != nil || len(rs6) != 1 || !rs6[0].v6 || rs6[0].localPort != 8737 || rs6[0].remote.String() != "10.0.0.7" || rs6[0].remotePort != 50000 || rs6[0].pid != 77 || rs6[0].state != tcpEstab {
		t.Fatalf("TCP6: %+v %v", rs6, err)
	}

	// UDP4 e UDP6.
	u4 := make([]byte, 4+udp4RowSize)
	binary.LittleEndian.PutUint32(u4, 1)
	binary.BigEndian.PutUint32(u4[4:], ip4("127.0.0.1"))
	binary.BigEndian.PutUint16(u4[8:], 53)
	binary.LittleEndian.PutUint32(u4[12:], 900)
	ru, err := parseUDP4(u4)
	if err != nil || len(ru) != 1 || !ru[0].udp || ru[0].localPort != 53 || ru[0].pid != 900 || !ru[0].local.IsLoopback() {
		t.Fatalf("UDP4: %+v %v", ru, err)
	}
	u6 := make([]byte, 4+udp6RowSize)
	binary.LittleEndian.PutUint32(u6, 1)
	binary.BigEndian.PutUint16(u6[4+20:], 5353)
	binary.LittleEndian.PutUint32(u6[4+24:], 901)
	ru6, err := parseUDP6(u6)
	if err != nil || len(ru6) != 1 || !ru6[0].udp || !ru6[0].v6 || ru6[0].localPort != 5353 || ru6[0].pid != 901 || !ru6[0].local.IsUnspecified() {
		t.Fatalf("UDP6: %+v %v", ru6, err)
	}
}

func TestDestinationAndScope(t *testing.T) {
	local := netip.MustParseAddr("192.168.1.34")
	for ip, want := range map[string]string{
		"127.0.0.1":       "local",
		"::1":             "local",
		"192.168.1.34":    "local", // lo stesso PC con il suo indirizzo
		"192.168.1.1":     "lan",
		"10.20.30.40":     "lan",
		"172.16.5.5":      "lan",
		"172.32.0.1":      "internet",
		"169.254.10.1":    "lan",
		"fe80::1":         "lan",
		"fd12:3456::1":    "lan",
		"100.64.0.1":      "lan",
		"100.127.255.254": "lan",
		"100.128.0.1":     "internet",
		"8.8.8.8":         "internet",
		"2a00:1450::200e": "internet",
		"::ffff:8.8.4.4":  "internet",
		"0.0.0.0":         "",
		"224.0.0.251":     "",
	} {
		if got := destination(netip.MustParseAddr(ip), local); got != want {
			t.Errorf("destination(%s) = %q, atteso %q", ip, got, want)
		}
	}
	if destination(netip.Addr{}, local) != "" {
		t.Error("indirizzo non valido")
	}
	for ip, want := range map[string]string{"0.0.0.0": "all", "::": "all", "127.0.0.1": "local", "::1": "local", "192.168.1.34": "specific", "fe80::5": "specific"} {
		if got := listenScope(netip.MustParseAddr(ip)); got != want {
			t.Errorf("listenScope(%s) = %q, atteso %q", ip, got, want)
		}
	}
}

func row(pid uint32, state uint32, local string, lport uint16, remote string, rport uint16) sockRow {
	r := sockRow{pid: pid, state: state, local: netip.MustParseAddr(local), localPort: lport, remotePort: rport}
	if remote != "" {
		r.remote = netip.MustParseAddr(remote)
	}
	r.v6 = r.local.Is6()
	return r
}

func TestAggregate(t *testing.T) {
	rs := []sockRow{
		row(4, tcpListen, "0.0.0.0", 445, "", 0),
		row(4, tcpListen, "::", 445, "", 0),
		row(4, tcpListen, "192.168.1.34", 139, "", 0),
		row(4, tcpListen, "10.0.0.5", 139, "", 0), // stessa porta su un altro indirizzo: un solo «specific»
		row(900, tcpListen, "127.0.0.1", 8737, "", 0),
		{udp: true, pid: 900, local: netip.MustParseAddr("0.0.0.0"), localPort: 5353},
		{udp: true, pid: 900, local: netip.MustParseAddr("0.0.0.0"), localPort: 5353},
		{udp: true, v6: true, pid: 900, local: netip.MustParseAddr("::"), localPort: 5353},
		row(1200, tcpEstab, "192.168.1.34", 50001, "140.82.112.3", 443),
		row(1200, tcpEstab, "192.168.1.34", 50002, "142.250.180.4", 443),
		row(1200, tcpSynSent, "192.168.1.34", 50003, "151.101.1.69", 443),
		row(1200, tcpEstab, "192.168.1.34", 50004, "192.168.1.10", 445),
		row(1200, tcpEstab, "127.0.0.1", 50005, "127.0.0.1", 8737),
		row(1200, tcpEstab, "192.168.1.34", 50006, "52.1.1.1", 80),
		row(1200, tcpEstab, "192.168.1.34", 50007, "52.1.1.2", 5228),
		row(1200, tcpEstab, "192.168.1.34", 50008, "52.1.1.3", 3478),
		row(1200, 11, "192.168.1.34", 50009, "52.1.1.4", 9999), // TIME_WAIT: non conta
		row(1200, 8, "192.168.1.34", 50010, "52.1.1.5", 9998),  // CLOSE_WAIT: non conta
		row(0, 11, "192.168.1.34", 50011, "52.1.1.6", 443),     // PID 0: di nessuno
		{udp: true, pid: 0, local: netip.MustParseAddr("0.0.0.0"), localPort: 1900},
	}
	m := aggregate(rs)
	if _, ok := m[0]; ok {
		t.Fatal("righe del PID 0 attribuite")
	}
	l4 := m[4].listen
	if len(l4) != 3 || l4[0] != (scan.ListenPort{Proto: "tcp", Port: 139, Scope: "specific"}) || l4[1] != (scan.ListenPort{Proto: "tcp", Port: 445, Scope: "all"}) || l4[2] != (scan.ListenPort{Proto: "tcp", Port: 445, Scope: "all", IPv6: true}) || m[4].conns != nil {
		t.Fatalf("System: %+v %+v", l4, m[4].conns)
	}
	l9 := m[900].listen
	if len(l9) != 3 || l9[0].Proto != "tcp" || l9[0].Scope != "local" || l9[1] != (scan.ListenPort{Proto: "udp", Port: 5353, Scope: "all"}) || !l9[2].IPv6 {
		t.Fatalf("doppioni o ordine: %+v", l9)
	}
	c := m[1200].conns
	if c == nil || c.Internet != 6 || c.LAN != 1 || c.Local != 1 || len(m[1200].listen) != 0 {
		t.Fatalf("connessioni: %+v", c)
	}
	if len(c.RemotePorts) != 5 || c.RemotePorts[0] != (scan.PortCount{Port: 443, Count: 3}) || c.RemotePorts[1].Port != 80 || c.RemotePorts[4].Port != 5228 {
		t.Fatalf("porte remote: %+v", c.RemotePorts)
	}
}

func TestPolarisSetAndParent(t *testing.T) {
	ps := []rawProc{
		{pid: 4, parent: 0, name: "System"},
		{pid: 100, parent: 50, name: "explorer.exe", created: 1000},
		{pid: 200, parent: 100, name: "polaris.exe", created: 2000},
		{pid: 300, parent: 200, name: "msedgewebview2.exe", created: 2100},
		{pid: 301, parent: 300, name: "msedgewebview2.exe", created: 2200}, // nipote
		{pid: 302, parent: 300, name: "msedgewebview2.exe", created: 0},    // ora non letta: nel dubbio no
		{pid: 400, parent: 200, name: "riciclato.exe", created: 1500},      // PID del padre riutilizzato
		{pid: 500, parent: 100, name: "notepad.exe", created: 3000},
		{pid: 600, parent: 999, name: "orfano.exe", created: 3000},     // padre terminato
		{pid: 700, parent: 500, name: "nato-prima.exe", created: 2500}, // padre nato dopo il figlio
	}
	got := polarisSet(ps, 200)
	if !got[200] || !got[300] || !got[301] || got[302] || got[400] || got[100] || got[500] || len(got) != 3 {
		t.Fatalf("albero di Polaris: %v", got)
	}
	if len(polarisSet(ps, 12345)) != 0 {
		t.Fatal("Polaris assente")
	}
	byPID := map[uint32]*rawProc{}
	for i := range ps {
		byPID[ps[i].pid] = &ps[i]
	}
	for i, want := range map[int]uint32{2: 100, 6: 0, 8: 999, 9: 0, 0: 0} {
		if got := parentOf(ps[i], byPID); got != want {
			t.Errorf("parentOf(%s) = %d, atteso %d", ps[i].name, got, want)
		}
	}
}

func TestSmallHelpers(t *testing.T) {
	if started(0) != "" || started(filetimeEpoch) != "" {
		t.Error("ora non letta")
	}
	// 1/1/2026 00:00:00 UTC = 1767225600 s dal 1970.
	if s := started(filetimeEpoch + 1767225600*10_000_000 + 4_000_000); s != "2026-01-01T00:00:00Z" {
		t.Errorf("ora di avvio: %q", s)
	}
	self := "S-1-5-21-1111-2222-3333-1001"
	for sid, want := range map[string]string{
		"":                             "unknown",
		self:                           "self",
		"s-1-5-21-1111-2222-3333-1001": "self",
		"S-1-5-18":                     "system",
		"S-1-5-19":                     "system",
		"S-1-5-20":                     "system",
		"S-1-5-21-1111-2222-3333-1002": "other",
		"S-1-5-90-0-1":                 "other",
	} {
		if got := ownerOf(sid, self); got != want {
			t.Errorf("ownerOf(%q) = %q, atteso %q", sid, got, want)
		}
	}
	for _, c := range []struct {
		proc, native, info uint16
		have               bool
		want               string
	}{
		{0, machineAMD64, 0, true, "x64"},
		{machineI386, machineAMD64, 0, true, "x86"},
		{machineI386, machineARM64, 0, true, "x86"},
		{machineARMNT, machineARM64, 0, true, "arm"},
		{0, machineARM64, machineAMD64, true, "x64-on-arm64"},
		{0, machineARM64, machineARM64, true, "arm64"},
		{0, machineARM64, 0, true, ""},
		{0, machineARM64, 0, false, "arm64"},
		{0, 0x1234, 0, true, ""},
	} {
		if got := archOf(c.proc, c.native, c.info, c.have); got != c.want {
			t.Errorf("archOf(%#x, %#x, %#x, %v) = %q, atteso %q", c.proc, c.native, c.info, c.have, got, c.want)
		}
	}
	for in, want := range map[[2]string]string{
		{"CDPUserSvc_4a5b6c", "user"}:  "CDPUserSvc",
		{"CDPUserSvc_4a5b6c", "win32"}: "CDPUserSvc_4a5b6c",
		{"Foo_bar", "user"}:            "Foo_bar",
		{"Foo_", "user"}:               "Foo_",
		{"Dnscache", "win32"}:          "Dnscache",
	} {
		typ := uint32(0x20)
		if in[1] == "user" {
			typ = 0xE0
		}
		if got := serviceName(in[0], typ); got != want {
			t.Errorf("serviceName(%q) = %q, atteso %q", in[0], got, want)
		}
	}
	for p, want := range map[string]bool{`C:\Windows\explorer.exe`: true, `d:/x.exe`: true, `\\server\share\a.exe`: true, "Registry": false, "": false, `C:x.exe`: false, `1:\a`: false} {
		if absWin(p) != want {
			t.Errorf("absWin(%q) != %v", p, want)
		}
	}
	for _, c := range []struct {
		pid, parent uint32
		name        string
		want        bool
	}{{0, 0, "[System Process]", true}, {4, 0, "System", true}, {120, 4, "Registry", true}, {2000, 4, "Memory Compression", true}, {400, 4, "smss.exe", false}, {500, 4, "SMSS.EXE", false}, {600, 7, "Registry", false}} {
		if kernelPseudo(c.pid, c.parent, c.name) != c.want {
			t.Errorf("kernelPseudo(%d, %d, %q) != %v", c.pid, c.parent, c.name, c.want)
		}
	}
	if got := cleanName("fatt\u202Eexe.pdf\x00\t"); got != "fattexe.pdf" {
		t.Errorf("cleanName: %q", got)
	}
	if n := len([]rune(cleanName(strings.Repeat("à", 400)))); n != 260 {
		t.Errorf("cleanName lungo: %d", n)
	}
	if !errors.Is(ErrUnavailable, errors.ErrUnsupported) || !strings.Contains(ErrUnavailable.Error(), "solo su Windows") {
		t.Error("ErrUnavailable")
	}
}

func TestVerifyOrder(t *testing.T) {
	for _, k := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "TEMP", "TMP"} {
		t.Setenv(k, "")
	}
	paths := []string{
		`C:\Windows\System32\svchost.exe`,
		`C:\Program Files\App\app.exe`,
		`C:\Users\anna\Downloads\tool.exe`,
		`C:\Windows\explorer.exe`,
		`C:\Users\anna\AppData\Local\Agent\agent.exe`,
		`D:\Giochi\gioco.exe`,
	}
	verifyOrder(paths, `C:\Users\anna`)
	want := []string{
		`C:\Users\anna\AppData\Local\Agent\agent.exe`,
		`C:\Users\anna\Downloads\tool.exe`,
		`C:\Program Files\App\app.exe`,
		`D:\Giochi\gioco.exe`,
		`C:\Windows\explorer.exe`,
		`C:\Windows\System32\svchost.exe`,
	}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Fatalf("ordine:\n%s", strings.Join(paths, "\n"))
	}
}

var ipv4RE = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

func TestBuild(t *testing.T) {
	ps := []rawProc{
		{pid: 0, name: "[System Process]", nameOnly: true},
		{pid: 4, name: "System", nameOnly: true},
		{pid: 812, parent: 700, name: "svchost.exe", opened: true, path: `C:\Windows\System32\svchost.exe`, created: filetimeEpoch + 1767225600*10_000_000, memBytes: 30 << 20, owner: "system", arch: "x64"},
		{pid: 900, parent: 700, name: "svchost.exe", opened: true, path: `c:\windows\system32\SVCHOST.EXE`, owner: "system", arch: "x64"},
		{pid: 1200, parent: 3000, name: "Browser.exe", opened: true, path: `C:\Users\anna\AppData\Local\Browser\browser.exe`, owner: "self", arch: "x64", memBytes: 1536 << 20},
		{pid: 1300, parent: 700, name: "antivirus.exe"},
		{pid: 3000, parent: 2900, name: "polaris.exe", opened: true, owner: "self", created: 10},
	}
	files := map[string]*scan.FileFacts{
		`c:\windows\system32\svchost.exe`:                 {Path: `C:\Windows\System32\svchost.exe`, Folder: "windows", Signature: &scan.FileSignature{Status: "valid", Signer: "Microsoft Windows", Catalog: true, Microsoft: true}},
		`c:\users\anna\appdata\local\browser\browser.exe`: {Path: `%USERPROFILE%\AppData\Local\Browser\browser.exe`, Folder: "appData", Version: "1.2.3.4"},
	}
	nets := aggregate([]sockRow{
		row(812, tcpListen, "0.0.0.0", 135, "", 0),
		row(1200, tcpEstab, "192.168.1.34", 50001, "140.82.112.3", 443),
		row(1200, tcpEstab, "fd00::2", 50002, "2a00:1450::200e", 443),
	})
	items := build(ps, files, map[uint32][]string{812: {"RpcEptMapper", "RpcSs"}}, nets, map[uint32]float64{1200: 12.345, 812: 0}, 3000)
	if len(items) != len(ps) {
		t.Fatalf("processi: %d", len(items))
	}
	var names []string
	for _, it := range items {
		names = append(names, it.Name)
	}
	if strings.Join(names, ",") != "[System Process],antivirus.exe,Browser.exe,polaris.exe,svchost.exe,svchost.exe,System" {
		t.Fatalf("ordine: %v", names)
	}
	by := map[uint32]scan.ProcessDetail{}
	for _, it := range items {
		by[it.PID] = it
	}
	if s := by[4]; s.File != nil || s.Owner != "" || s.Access != "" {
		t.Fatalf("System: %+v", s)
	}
	if a := by[1300]; a.Access != "none" || a.Owner != "unknown" || a.File != nil || a.ParentPID != 700 {
		t.Fatalf("non apribile: %+v", a)
	}
	sv := by[812]
	if sv.File == nil || !sv.File.Signature.Microsoft || sv.Started != "2026-01-01T00:00:00Z" || sv.MemoryMB != 30 || sv.CPUPct == nil || *sv.CPUPct != 0 || len(sv.Services) != 2 || len(sv.Listen) != 1 {
		t.Fatalf("svchost: %+v", sv)
	}
	if by[900].File == nil || by[900].File == sv.File {
		t.Fatal("ogni processo ha la sua copia dei fatti sul file")
	}
	br := by[1200]
	if br.CPUPct == nil || *br.CPUPct != 12.3 || br.MemoryMB != 1536 || br.Conns == nil || br.Conns.Internet != 2 || br.Polaris {
		t.Fatalf("browser: %+v", br)
	}
	if !by[3000].Polaris || by[3000].File != nil {
		t.Fatalf("Polaris: %+v", by[3000])
	}
	// Nessun indirizzo nel JSON (tolte le versioni, che sembrano indirizzi).
	b, _ := json.Marshal(scan.ProcessesData{Items: items})
	raw := regexp.MustCompile(`"version":"[^"]*"`).ReplaceAllString(string(b), "")
	if m := ipv4RE.FindString(raw); m != "" || strings.Contains(raw, "2a00") || strings.Contains(raw, "140.82") || strings.Contains(raw, "anna") {
		t.Fatalf("dati da non esportare nel JSON (%q): %s", m, raw)
	}
}
