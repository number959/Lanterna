//go:build windows

package procs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"lanterna/internal/pcinfo"
	"lanterna/internal/scan"
)

var (
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procK32GetProcessMemoryInfo = kernel32.NewProc("K32GetProcessMemoryInfo")
	procGetProcessInformation   = kernel32.NewProc("GetProcessInformation")
	// GetExtendedTcpTable e GetExtendedUdpTable non sono in x/sys.
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	afInet              = 2  // AF_INET
	afInet6             = 23 // AF_INET6
	tcpTableOwnerPIDAll = 5  // TCP_TABLE_OWNER_PID_ALL (iprtrmib.h)
	udpTableOwnerPID    = 1  // UDP_TABLE_OWNER_PID
	// processMachineTypeInfo è ProcessMachineTypeInfo
	// (PROCESS_INFORMATION_CLASS, processthreadsapi.h), dalla build 22000.
	processMachineTypeInfo = 9
)

// processMemoryCounters è PROCESS_MEMORY_COUNTERS (psapi.h): 72 byte a 64
// bit, 40 a 32 bit.
type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// processMachineInformation è PROCESS_MACHINE_INFORMATION: USHORT
// ProcessMachine @0, USHORT Res0 @2, MACHINE_ATTRIBUTES (DWORD) @4.
type processMachineInformation struct {
	ProcessMachine    uint16
	Res0              uint16
	MachineAttributes uint32
}

const ptrSize = unsafe.Sizeof(uintptr(0))

var (
	_ [unsafe.Sizeof(processMemoryCounters{}) - (40 + 8*(ptrSize-4))]struct{}
	_ [(40 + 8*(ptrSize-4)) - unsafe.Sizeof(processMemoryCounters{})]struct{}
	_ [unsafe.Sizeof(processMachineInformation{}) - 8]struct{}
	_ [8 - unsafe.Sizeof(processMachineInformation{})]struct{}
)

// Read legge i processi in esecuzione, con file, firma, utente (categoria),
// servizi e connessioni riassunte. cpu sono i carichi per PID misurati a
// fine analisi da una misura cominciata a since (nil e l'ora zero se non
// misurati): valgono solo per i processi nati prima, perché un PID si
// ricicla. Tutto entro readTimeout: se la verifica delle firme non finisce,
// Partial e i file restanti senza firma.
func Read(ctx context.Context, cpu map[uint32]float64, since time.Time) (*scan.ProcessesData, error) {
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	list, err := snapshot()
	if err != nil {
		return nil, fmt.Errorf("elenco dei processi non leggibile: %w", err)
	}
	out := &scan.ProcessesData{At: time.Now().UTC().Format(time.RFC3339), Items: []scan.ProcessDetail{}}
	// Le tabelle delle connessioni subito dopo l'elenco: i PID si riciclano.
	socks, connsOK := sockets()
	services := servicesByPID()
	self := uint32(os.Getpid())
	me := windows.GetCurrentProcessToken()
	out.Elevated = me.IsElevated()
	selfSID := ""
	if tu, err := me.GetTokenUser(); err == nil && tu.User.Sid != nil {
		selfSID = tu.User.Sid.String()
	}
	machineInfo := windows.RtlGetVersion().BuildNumber >= 22000 && procGetProcessInformation.Find() == nil
	buf := make([]uint16, windows.MAX_LONG_PATH)
	ps := make([]rawProc, 0, len(list))
	partial := false
	for _, e := range list {
		p := rawProc{pid: e.pid, parent: e.parent, name: e.name}
		switch {
		case kernelPseudo(p.pid, p.parent, p.name):
			p.nameOnly = true
			// Solo l'ora di nascita, per il carico per PID (measured): la
			// misura del carico conta anche Registry e Memory Compression.
			p.created = createdOf(p.pid)
		case ctx.Err() != nil:
			p.nameOnly, partial = true, true
		default:
			if readProc(&p, buf, selfSID, machineInfo) {
				continue // terminato tra l'elenco e l'apertura
			}
			if !p.opened {
				out.Unreadable++
			}
		}
		ps = append(ps, p)
	}
	files, filesPartial := fileFacts(ctx, ps)
	var nets map[uint32]*netInfo
	if connsOK {
		nets = aggregate(socks)
		out.ConnsRead = true
	}
	out.Items = build(ps, files, services, nets, load{cpu: cpu, since: filetime(since)}, self, pcinfo.DefaultCleaner().Text)
	out.Partial = partial || filesPartial || ctx.Err() != nil
	return out, nil
}

type entry struct {
	pid, parent uint32
	name        string
}

// snapshot elenca i processi con Toolhelp32: PID, padre e nome del file.
func snapshot() ([]entry, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)
	var out []entry
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		out = append(out, entry{pid: pe.ProcessID, parent: pe.ParentProcessID, name: cleanName(windows.UTF16ToString(pe.ExeFile[:]))})
	}
	if len(out) == 0 {
		if err == nil {
			err = errors.New("nessun processo")
		}
		return nil, err
	}
	return out, nil
}

// readProc apre il processo con i diritti minimi
// (PROCESS_QUERY_LIMITED_INFORMATION, ammesso anche verso i processi
// protetti) e ne legge percorso, ora di avvio, memoria, architettura e
// account. Restituisce true se il processo non esiste più.
func readProc(p *rawProc, buf []uint16, selfSID string, machineInfo bool) (gone bool) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid)
	if err != nil {
		// ERROR_INVALID_PARAMETER: nessun processo con quel PID.
		return errors.Is(err, windows.ERROR_INVALID_PARAMETER)
	}
	defer windows.CloseHandle(h)
	p.opened = true
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil && n > 0 && int(n) <= len(buf) {
		p.path = windows.UTF16ToString(buf[:n])
		// Un programma avviato con un nome breve 8.3 (C:\Users\MARIO~1\...)
		// riporta quel nome: con quello lungo il profilo si riconosce.
		if strings.Contains(p.path, "~") {
			if short, err := windows.UTF16PtrFromString(p.path); err == nil {
				if m, err := windows.GetLongPathName(short, &buf[0], uint32(len(buf))); err == nil && m > 0 && int(m) < len(buf) {
					p.path = windows.UTF16ToString(buf[:m])
				}
			}
		}
	}
	p.created = createdOfHandle(h)
	var m processMemoryCounters
	m.CB = uint32(unsafe.Sizeof(m))
	if r, _, _ := procK32GetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&m)), uintptr(m.CB)); r != 0 {
		p.memBytes = uint64(m.WorkingSetSize)
	}
	p.arch = archOfHandle(h, machineInfo)
	p.owner = "unknown"
	var tok windows.Token
	// Per i processi di altri account serve di solito l'amministratore.
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) == nil {
		if tu, err := tok.GetTokenUser(); err == nil && tu.User.Sid != nil {
			p.owner = ownerOf(tu.User.Sid.String(), selfSID)
		}
		p.elevated = tok.IsElevated()
		tok.Close()
	}
	return false
}

// createdOfHandle restituisce l'ora di nascita del processo (FILETIME), 0
// se non si legge.
func createdOfHandle(h windows.Handle) int64 {
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &e, &k, &u) != nil {
		return 0
	}
	return int64(c.HighDateTime)<<32 | int64(c.LowDateTime)
}

// createdOf restituisce l'ora di nascita di uno pseudo-processo del nucleo
// (Registry, Memory Compression), di cui non si legge altro; 0 per Idle e
// System, che non si aprono, e se non si legge.
func createdOf(pid uint32) int64 {
	if pid == 0 || pid == 4 {
		return 0
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	return createdOfHandle(h)
}

func archOfHandle(h windows.Handle, machineInfo bool) string {
	var pm, nm uint16
	if err := windows.IsWow64Process2(h, &pm, &nm); err != nil {
		// Windows 10 prima della 1709: solo WOW64 sì o no.
		var wow bool
		if windows.IsWow64Process(h, &wow) != nil {
			return ""
		}
		if wow {
			return "x86"
		}
		if runtime.GOARCH == "amd64" {
			return "x64"
		}
		return ""
	}
	var info uint16
	if pm == machineUnknown && nm == machineARM64 && machineInfo {
		var pmi processMachineInformation
		if r, _, _ := procGetProcessInformation.Call(uintptr(h), processMachineTypeInfo, uintptr(unsafe.Pointer(&pmi)), unsafe.Sizeof(pmi)); r != 0 {
			info = pmi.ProcessMachine
		}
	}
	return archOf(pm, nm, info, machineInfo)
}

// sockets legge le tabelle TCP e UDP (IPv4 e IPv6) con il PID di ogni riga.
// ok è falso se una tabella non si legge: le connessioni allora non si
// riportano affatto, piuttosto che a metà.
func sockets() ([]sockRow, bool) {
	tables := []struct {
		proc  *windows.LazyProc
		af    uintptr
		class uintptr
		parse func([]byte) ([]sockRow, error)
	}{
		{procGetExtendedTcpTable, afInet, tcpTableOwnerPIDAll, parseTCP4},
		{procGetExtendedTcpTable, afInet6, tcpTableOwnerPIDAll, parseTCP6},
		{procGetExtendedUdpTable, afInet, udpTableOwnerPID, parseUDP4},
		{procGetExtendedUdpTable, afInet6, udpTableOwnerPID, parseUDP6},
	}
	var all []sockRow
	for _, t := range tables {
		b, err := extTable(t.proc, t.af, t.class)
		if err != nil {
			if t.af == afInet6 && errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
				continue // IPv6 assente su questo PC: nessuna riga
			}
			return nil, false
		}
		rs, err := t.parse(b)
		if err != nil {
			return nil, false
		}
		all = append(all, rs...)
	}
	return all, true
}

// extTable chiama GetExtendedTcpTable o GetExtendedUdpTable con un buffer
// allineato a 8, ripetendo se le connessioni crescono nel frattempo. Il
// ritorno è l'errore stesso (DWORD), non GetLastError.
func extTable(p *windows.LazyProc, af, class uintptr) ([]byte, error) {
	if err := p.Find(); err != nil {
		return nil, err
	}
	size := uint32(16 << 10)
	for i := 0; i < 5; i++ {
		buf := make([]uint64, (size+7)/8)
		n := uint32(len(buf) * 8)
		r, _, _ := p.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0, af, class, 0)
		switch e := syscall.Errno(uint32(r)); e {
		case 0:
			return unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), len(buf)*8), nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			if n > 64<<20 {
				return nil, e
			}
			size = n + n/4 + 1024 // margine: le connessioni cambiano tra due chiamate
		default:
			return nil, e
		}
	}
	return nil, windows.ERROR_INSUFFICIENT_BUFFER
}

// servicesByPID restituisce i nomi brevi dei servizi attivi per processo.
// Lo SCM si apre con i soli diritti di connessione ed elenco, concessi agli
// utenti autenticati (svc/mgr.Connect chiederebbe l'accesso completo e
// senza amministratore fallirebbe). nil se non leggibile.
func servicesByPID() map[uint32][]string {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil
	}
	defer windows.CloseServiceHandle(h)
	out := map[uint32][]string{}
	var resume uint32
	size := uint32(64 << 10)
	entrySize := unsafe.Sizeof(windows.ENUM_SERVICE_STATUS_PROCESS{})
	for i := 0; i < 64; i++ {
		buf := make([]uint64, (size+7)/8) // le voci contengono puntatori: allineato a 8
		var needed, count uint32
		err := windows.EnumServicesStatusEx(h, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_ACTIVE,
			(*byte)(unsafe.Pointer(&buf[0])), uint32(len(buf)*8), &needed, &count, &resume, nil)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			break
		}
		if count > 0 && uintptr(count) <= uintptr(len(buf)*8)/entrySize {
			for _, s := range unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count) {
				pid := s.ServiceStatusProcess.ProcessId
				if pid == 0 || s.ServiceName == nil {
					continue
				}
				out[pid] = append(out[pid], serviceName(windows.UTF16PtrToString(s.ServiceName), s.ServiceStatusProcess.ServiceType))
			}
		}
		if err == nil {
			break
		}
		// Microsoft: il buffer non serve più grande di 256 KB; il resto con resume.
		if needed > size {
			size = min(needed, 256<<10)
		}
	}
	for pid, names := range out {
		sort.Strings(names)
		k := 0
		for i, n := range names {
			if i == 0 || n != names[k-1] {
				names[k] = n
				k++
			}
		}
		out[pid] = names[:k]
	}
	return out
}

// fileFacts verifica una volta per file (svchost e le schede dei browser
// sono decine di processi con lo stesso eseguibile), con pochi file insieme.
// Allo scadere del contesto non aspetta le verifiche in corso: i file
// restanti hanno solo percorso e cartella, e partial è vero. Le unità
// rimovibili e di rete collegate a una lettera le riconosce Facts, che non
// apre i file in rete (condivisioni e unità di rete): firma "unknown".
func fileFacts(ctx context.Context, ps []rawProc) (map[string]*scan.FileFacts, bool) {
	var list []string
	seen := map[string]bool{}
	for _, p := range ps {
		k := strings.ToLower(p.path)
		if p.opened && absWin(p.path) && !seen[k] {
			seen[k] = true
			list = append(list, p.path)
		}
	}
	c := fileChecker()
	verifyOrder(list, c.Profile)
	results := map[string]*scan.FileFacts{}
	var mu sync.Mutex
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < sigWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				f := c.Facts(ctx, p)
				mu.Lock()
				results[strings.ToLower(p)] = f
				mu.Unlock()
			}
		}()
	}
feed:
	for _, p := range list {
		select {
		case jobs <- p:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	mu.Lock()
	out := make(map[string]*scan.FileFacts, len(list))
	for k, v := range results {
		out[k] = v
	}
	mu.Unlock()
	partial := false
	for _, p := range list {
		k := strings.ToLower(p)
		if out[k] == nil {
			// Tempo scaduto: Facts non tocca il disco e dà solo percorso e
			// cartella.
			partial = true
			out[k] = c.Facts(ctx, p)
		}
	}
	return out, partial
}
