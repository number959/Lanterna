// Package procs legge i processi in esecuzione, come Process Explorer e
// TCPView: file, firma digitale, utente (solo la categoria), servizi ospitati
// e connessioni di rete riassunte. Sola lettura: non termina processi e non
// chiude connessioni.
//
// Privacy: mai la riga di comando, mai SID o nomi di account, mai indirizzi
// remoti. Gli indirizzi delle tabelle TCP e UDP restano dentro il pacchetto:
// ne escono solo porte, ambito delle porte in ascolto e conteggi per
// destinazione (questo PC, rete locale, Internet). I percorsi passano da
// pulitore comune (pcinfo.Cleaner).
//
// La parte che non dipende da Windows (indirizzi, aggregazione delle
// connessioni, albero di Polaris, ordinamento) sta qui ed è provata ovunque;
// le letture native in procs_windows.go.
package procs

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"lanterna/internal/scan"
	"lanterna/internal/sign"
)

// readTimeout è il tempo massimo di una lettura completa: la verifica delle
// firme, la parte lunga, si ferma lì e il risultato è parziale.
const readTimeout = 25 * time.Second

// sigWorkers è il numero di file verificati insieme: la sicurezza di
// WinVerifyTrust su più thread non è documentata, quindi pochi.
const sigWorkers = 3

// errUnavailable è l'errore fuori da Windows; per errors.Is vale
// errors.ErrUnsupported, così il server risponde 501.
type errUnavailable struct{}

func (errUnavailable) Error() string {
	return "lettura dei processi e delle connessioni disponibile solo su Windows"
}
func (errUnavailable) Is(target error) bool { return target == errors.ErrUnsupported }

// ErrUnavailable dice che la lettura non è disponibile su questo sistema.
var ErrUnavailable error = errUnavailable{}

// Stati delle righe TCP (MIB_TCP_STATE, tcpmib.h).
const (
	tcpListen   = 2
	tcpSynSent  = 3
	tcpSynRcvd  = 4
	tcpEstab    = 5
	topRemPorts = 5 // porte remote riportate per processo
)

// sockRow è una riga delle tabelle TCP o UDP. Gli indirizzi non escono mai
// dal pacchetto.
type sockRow struct {
	udp        bool
	v6         bool // dalla tabella IPv6
	pid        uint32
	state      uint32 // solo TCP
	local      netip.Addr
	localPort  uint16
	remote     netip.Addr // solo TCP
	remotePort uint16
}

// Righe delle tabelle estese di iphlpapi (tcpmib.h, udpmib.h): solo DWORD e
// UCHAR, quindi gli stessi scostamenti su 386, amd64 e arm64; dwNumEntries a
// 0 e le righe da 4. Porte in ordine di rete nei due byte bassi del DWORD,
// indirizzi IPv4 nel formato di in_addr, IPv6 in ordine di rete.
const (
	tcp4RowSize = 24 // MIB_TCPROW_OWNER_PID
	tcp6RowSize = 56 // MIB_TCP6ROW_OWNER_PID
	udp4RowSize = 12 // MIB_UDPROW_OWNER_PID
	udp6RowSize = 28 // MIB_UDP6ROW_OWNER_PID
)

var errTable = errors.New("tabella delle connessioni troncata")

func rows(b []byte, size int) (int, error) {
	if len(b) < 4 {
		return 0, errTable
	}
	n := int(binary.LittleEndian.Uint32(b))
	if n < 0 || n > (len(b)-4)/size {
		return 0, errTable
	}
	return n, nil
}

func port(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func addr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b[:4])) }

func addr6(b []byte) netip.Addr { return netip.AddrFrom16([16]byte(b[:16])).Unmap() }

// parseTCP4 legge MIB_TCPTABLE_OWNER_PID: dwState @0, dwLocalAddr @4,
// dwLocalPort @8, dwRemoteAddr @12, dwRemotePort @16, dwOwningPid @20.
func parseTCP4(b []byte) ([]sockRow, error) {
	n, err := rows(b, tcp4RowSize)
	out := make([]sockRow, 0, n)
	for i := 0; i < n; i++ {
		r := b[4+i*tcp4RowSize:]
		out = append(out, sockRow{
			state: binary.LittleEndian.Uint32(r), local: addr4(r[4:]), localPort: port(r[8:]),
			remote: addr4(r[12:]), remotePort: port(r[16:]), pid: binary.LittleEndian.Uint32(r[20:]),
		})
	}
	return out, err
}

// parseTCP6 legge MIB_TCP6TABLE_OWNER_PID: ucLocalAddr @0, dwLocalScopeId
// @16, dwLocalPort @20, ucRemoteAddr @24, dwRemoteScopeId @40, dwRemotePort
// @44, dwState @48, dwOwningPid @52.
func parseTCP6(b []byte) ([]sockRow, error) {
	n, err := rows(b, tcp6RowSize)
	out := make([]sockRow, 0, n)
	for i := 0; i < n; i++ {
		r := b[4+i*tcp6RowSize:]
		out = append(out, sockRow{
			v6: true, local: addr6(r), localPort: port(r[20:]), remote: addr6(r[24:]), remotePort: port(r[44:]),
			state: binary.LittleEndian.Uint32(r[48:]), pid: binary.LittleEndian.Uint32(r[52:]),
		})
	}
	return out, err
}

// parseUDP4 legge MIB_UDPTABLE_OWNER_PID: dwLocalAddr @0, dwLocalPort @4,
// dwOwningPid @8.
func parseUDP4(b []byte) ([]sockRow, error) {
	n, err := rows(b, udp4RowSize)
	out := make([]sockRow, 0, n)
	for i := 0; i < n; i++ {
		r := b[4+i*udp4RowSize:]
		out = append(out, sockRow{udp: true, local: addr4(r), localPort: port(r[4:]), pid: binary.LittleEndian.Uint32(r[8:])})
	}
	return out, err
}

// parseUDP6 legge MIB_UDP6TABLE_OWNER_PID: ucLocalAddr @0, dwLocalScopeId
// @16, dwLocalPort @20, dwOwningPid @24.
func parseUDP6(b []byte) ([]sockRow, error) {
	n, err := rows(b, udp6RowSize)
	out := make([]sockRow, 0, n)
	for i := 0; i < n; i++ {
		r := b[4+i*udp6RowSize:]
		out = append(out, sockRow{udp: true, v6: true, local: addr6(r), localPort: port(r[20:]), pid: binary.LittleEndian.Uint32(r[24:])})
	}
	return out, err
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// destination classifica l'indirizzo remoto di una connessione: local (questo
// PC), lan (indirizzi privati RFC 1918, fc00::/7, link-local, CGNAT
// 100.64/10), internet (il resto); vuoto se non è una destinazione vera.
func destination(remote, local netip.Addr) string {
	remote, local = remote.Unmap(), local.Unmap()
	switch {
	case !remote.IsValid() || remote.IsUnspecified() || remote.IsMulticast() || remote == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return ""
	case remote.IsLoopback() || remote == local:
		return "local"
	case remote.IsPrivate() || remote.IsLinkLocalUnicast() || cgnat.Contains(remote):
		return "lan"
	}
	return "internet"
}

// listenScope dice su quali indirizzi accetta connessioni una porta: all
// (0.0.0.0 o ::, «any interface»), local (solo questo PC), specific (un
// indirizzo della rete).
func listenScope(local netip.Addr) string {
	local = local.Unmap()
	switch {
	case !local.IsValid() || local.IsUnspecified():
		return "all"
	case local.IsLoopback():
		return "local"
	}
	return "specific"
}

// netInfo è la rete di un processo, già senza indirizzi.
type netInfo struct {
	listen []scan.ListenPort
	conns  *scan.ConnSummary
}

// aggregate riassume le righe per processo: porte in ascolto (TCP in
// LISTEN e UDP aperte) senza doppioni, connessioni TCP stabilite o in corso
// contate per destinazione con le porte remote più usate. Le righe del PID 0
// (TIME_WAIT, o UDP senza processo noto) non appartengono a nessuno.
func aggregate(rs []sockRow) map[uint32]*netInfo {
	out := map[uint32]*netInfo{}
	type lkey struct {
		pid uint32
		lp  scan.ListenPort
	}
	seen := map[lkey]bool{}
	ports := map[uint32]map[uint16]int{}
	get := func(pid uint32) *netInfo {
		ni := out[pid]
		if ni == nil {
			ni = &netInfo{}
			out[pid] = ni
		}
		return ni
	}
	for _, r := range rs {
		if r.pid == 0 {
			continue
		}
		if r.udp || r.state == tcpListen {
			lp := scan.ListenPort{Proto: "tcp", Port: r.localPort, Scope: listenScope(r.local), IPv6: r.v6}
			if r.udp {
				lp.Proto = "udp"
			}
			k := lkey{pid: r.pid, lp: lp}
			if !seen[k] {
				seen[k] = true
				ni := get(r.pid)
				ni.listen = append(ni.listen, lp)
			}
			continue
		}
		if r.state != tcpEstab && r.state != tcpSynSent && r.state != tcpSynRcvd {
			continue
		}
		dest := destination(r.remote, r.local)
		if dest == "" {
			continue
		}
		ni := get(r.pid)
		if ni.conns == nil {
			ni.conns = &scan.ConnSummary{}
		}
		switch dest {
		case "local":
			ni.conns.Local++
		case "lan":
			ni.conns.LAN++
		default:
			ni.conns.Internet++
		}
		if ports[r.pid] == nil {
			ports[r.pid] = map[uint16]int{}
		}
		ports[r.pid][r.remotePort]++
	}
	for pid, ni := range out {
		sort.Slice(ni.listen, func(i, j int) bool {
			a, b := ni.listen[i], ni.listen[j]
			if a.Proto != b.Proto {
				return a.Proto < b.Proto
			}
			if a.Port != b.Port {
				return a.Port < b.Port
			}
			if a.IPv6 != b.IPv6 {
				return !a.IPv6
			}
			return a.Scope < b.Scope
		})
		if ni.conns != nil {
			ni.conns.RemotePorts = topPorts(ports[pid], topRemPorts)
		}
	}
	return out
}

// topPorts restituisce le n porte più usate, a parità la più bassa prima.
func topPorts(m map[uint16]int, n int) []scan.PortCount {
	out := make([]scan.PortCount, 0, len(m))
	for p, c := range m {
		out = append(out, scan.PortCount{Port: p, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Count > out[j].Count || (out[i].Count == out[j].Count && out[i].Port < out[j].Port)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// rawProc è un processo letto da Windows, prima di diventare un
// scan.ProcessDetail. Path è il percorso vero (non esportato così).
type rawProc struct {
	pid, parent uint32
	name        string
	path        string
	created     int64 // FILETIME (unità da 100 ns dal 1601); 0 se non letto
	memBytes    uint64
	arch        string
	owner       string
	elevated    bool
	opened      bool // aperto con PROCESS_QUERY_LIMITED_INFORMATION
	// nameOnly: del processo si riporta solo il nome (pseudo-processo del
	// nucleo, oppure tempo finito prima di leggerlo).
	nameOnly bool
}

// kernelPseudo riconosce i processi del nucleo senza un file eseguibile:
// PID 0 (Idle) e 4 (System), e i figli di System senza «.exe» nel nome
// (Registry, Memory Compression, Secure System). Il criterio per i figli di
// System viene dalla pratica, non da un documento Microsoft: smss.exe, figlio
// di System con un file vero, resta un processo normale.
func kernelPseudo(pid, parent uint32, name string) bool {
	if pid == 0 || pid == 4 {
		return true
	}
	return parent == 4 && !strings.HasSuffix(strings.ToLower(name), ".exe")
}

// polarisSet restituisce Polaris (il PID self) e i suoi discendenti, a ogni
// livello (le finestre msedgewebview2 nate da Polaris e i loro figli). Il PID
// si ricicla: un figlio vale solo se è nato dopo il padre, con entrambe le ore
// lette; nel dubbio il processo non si segna, così non sparisce dai giudizi.
func polarisSet(ps []rawProc, self uint32) map[uint32]bool {
	byPID := map[uint32]*rawProc{}
	kids := map[uint32][]*rawProc{}
	for i := range ps {
		p := &ps[i]
		byPID[p.pid] = p
		if p.pid != p.parent {
			kids[p.parent] = append(kids[p.parent], p)
		}
	}
	out := map[uint32]bool{}
	root := byPID[self]
	if root == nil {
		return out
	}
	out[self] = true
	queue := []*rawProc{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, k := range kids[p.pid] {
			if out[k.pid] || k.created == 0 || p.created == 0 || k.created < p.created {
				continue
			}
			out[k.pid] = true
			queue = append(queue, k)
		}
	}
	return out
}

// parentOf restituisce il PID del padre da esportare: 0 se il padre attuale
// con quel PID è nato dopo il figlio (il PID è stato riutilizzato, come
// avverte Microsoft per Win32_Process). Un padre non più in esecuzione resta:
// dice da chi è nato il processo.
func parentOf(p rawProc, byPID map[uint32]*rawProc) uint32 {
	if p.parent == p.pid {
		return 0
	}
	if q := byPID[p.parent]; q != nil && q.created != 0 && p.created != 0 && q.created > p.created {
		return 0
	}
	return p.parent
}

// filetimeEpoch è la differenza tra il 1601 (FILETIME) e il 1970, in unità da
// 100 ns.
const filetimeEpoch = 116444736000000000

// started scrive l'ora di avvio in RFC 3339 (UTC, al secondo).
func started(ft int64) string {
	if ft <= filetimeEpoch {
		return ""
	}
	return time.Unix(0, (ft-filetimeEpoch)*100).UTC().Format(time.RFC3339)
}

// ownerOf classifica l'account del processo dal SID in forma di testo, che
// non esce mai dal pacchetto: self (chi usa Polaris), system (S-1-5-18
// SYSTEM, -19 LOCAL SERVICE, -20 NETWORK SERVICE), other (un altro account,
// compresi gli account virtuali dei servizi, di DWM e dei caratteri),
// unknown (token non leggibile).
func ownerOf(sid, self string) string {
	switch {
	case sid == "":
		return "unknown"
	case self != "" && strings.EqualFold(sid, self):
		return "self"
	case sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20":
		return "system"
	}
	return "other"
}

// Macchine di IMAGE_FILE_MACHINE_* (winnt.h).
const (
	machineUnknown = 0
	machineI386    = 0x014c
	machineAMD64   = 0x8664
	machineARM64   = 0xAA64
	machineARMNT   = 0x01c4
)

func machineName(m uint16) string {
	switch m {
	case machineI386:
		return "x86"
	case machineAMD64:
		return "x64"
	case machineARM64:
		return "arm64"
	case machineARMNT:
		return "arm"
	}
	return ""
}

// archOf ricava l'architettura da IsWow64Process2 (proc vale 0 se il processo
// non è WOW64) e, sui PC ARM64, da GetProcessInformation
// (ProcessMachineTypeInfo, dalla build 22000): i processi x64 emulati non
// sono WOW64. haveInfo: la funzione esiste su questo Windows; info 0: non
// letta. Nel dubbio vuoto.
func archOf(proc, native, info uint16, haveInfo bool) string {
	if proc != machineUnknown {
		return machineName(proc)
	}
	if native == machineARM64 {
		switch {
		case !haveInfo:
			return "arm64" // Windows 10 su ARM: niente emulazione x64
		case info == machineAMD64:
			return "x64-on-arm64"
		case info == machineARM64:
			return "arm64"
		}
		return ""
	}
	return machineName(native)
}

// serviceName toglie dai servizi per utente (bit 0x40 del tipo) il suffisso
// _LUID, che cambia a ogni accesso: «CDPUserSvc_4a5b6c» diventa
// «CDPUserSvc» (Microsoft, «Per-user services in Windows»).
func serviceName(name string, typ uint32) string {
	if typ&0x40 == 0 {
		return name
	}
	i := strings.LastIndexByte(name, '_')
	if i <= 0 || i == len(name)-1 {
		return name
	}
	for _, r := range name[i+1:] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return name
		}
	}
	return name[:i]
}

// absWin dice se il percorso è assoluto in Windows (unità o condivisione):
// solo questi si verificano (Registry, Memory Compression e simili non hanno
// un file).
func absWin(p string) bool {
	if len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		c := p[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return strings.HasPrefix(p, `\\`)
}

// build compone i processi da esportare: nessun indirizzo, percorsi già
// ripuliti dai fatti sui file, CPU dalla misura del carico se c'è.
func build(ps []rawProc, files map[string]*scan.FileFacts, services map[uint32][]string, nets map[uint32]*netInfo, cpu map[uint32]float64, self uint32) []scan.ProcessDetail {
	byPID := map[uint32]*rawProc{}
	for i := range ps {
		byPID[ps[i].pid] = &ps[i]
	}
	mine := polarisSet(ps, self)
	out := make([]scan.ProcessDetail, 0, len(ps))
	for _, p := range ps {
		d := scan.ProcessDetail{PID: p.pid, ParentPID: parentOf(p, byPID), Name: p.name, Polaris: mine[p.pid], Services: services[p.pid]}
		if ni := nets[p.pid]; ni != nil {
			d.Listen, d.Conns = ni.listen, ni.conns
		}
		if v, ok := cpu[p.pid]; ok {
			v = math.Round(v*10) / 10
			d.CPUPct = &v
		}
		if !p.nameOnly {
			if !p.opened {
				d.Access, d.Owner = "none", "unknown"
			} else {
				d.Owner, d.Elevated, d.Arch, d.Started = p.owner, p.elevated, p.arch, started(p.created)
				if p.memBytes > 0 {
					d.MemoryMB = math.Round(float64(p.memBytes)/(1<<20)*10) / 10
				}
				if f := files[strings.ToLower(p.path)]; f != nil {
					cp := *f
					d.File = &cp
				}
			}
		}
		out = append(out, d)
	}
	sortItems(out)
	return out
}

// cleanName ripulisce il nome del file del processo: niente caratteri di
// controllo né di formato (un U+202E rovescerebbe la lettura, come in
// «gpj.exe» mostrato al contrario), al massimo 260 caratteri.
func cleanName(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n++; n > 260 {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// sortItems ordina per nome (senza maiuscole) e PID: l'interfaccia riordina
// da sé.
func sortItems(items []scan.ProcessDetail) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := strings.ToLower(items[i].Name), strings.ToLower(items[j].Name)
		if a != b {
			return a < b
		}
		return items[i].PID < items[j].PID
	})
}

// verifyOrder ordina i file da verificare: prima quelli nelle cartelle che
// l'utente può scrivere (AppData, Download, temporanee...), poi gli altri,
// per ultimi quelli di Windows. Se il tempo finisce, restano senza verifica
// i meno interessanti.
func verifyOrder(paths []string, profile string) {
	rank := make(map[string]int, len(paths))
	for _, p := range paths {
		switch f := sign.FolderOf(p, profile); {
		case sign.UserWritable(f):
			rank[p] = 0
		case f == "windows":
			rank[p] = 2
		default:
			rank[p] = 1
		}
	}
	sort.SliceStable(paths, func(i, j int) bool {
		if rank[paths[i]] != rank[paths[j]] {
			return rank[paths[i]] < rank[paths[j]]
		}
		return strings.ToLower(paths[i]) < strings.ToLower(paths[j])
	})
}

// Il Checker delle firme è quello comune (sign.Shared), condiviso con
// l'avvio automatico: lo stesso file si verifica una volta sola finché non
// cambia, e i percorsi passano dal pulitore comune (profili, nome
// dell'utente, SID, e-mail).
func fileChecker() *sign.Checker { return sign.Shared() }
