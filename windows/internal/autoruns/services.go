package autoruns

import (
	"strings"

	"lanterna/internal/scan"
)

// Tipi e modi di avvio dei servizi (winsvc.h, CreateServiceW).
const (
	svcKernelDriver     = 0x1
	svcFileSystemDriver = 0x2
	svcRecognizerDriver = 0x8
	svcWin32Own         = 0x10
	svcWin32Share       = 0x20
	// svcUserService è il bit dei servizi per utente («Per-user services in
	// Windows»): il modello e le sue copie per ogni accesso, che hanno il
	// suffisso _LUID nel nome.
	svcUserService = 0x40
)

// rawService è un servizio o driver come lo restituisce Gestione servizi.
type rawService struct {
	Name, Display string
	Type, Start   uint32
	Delayed       bool
	Running       bool
	// Image è lpBinaryPathName (ImagePath): riga di comando del servizio o
	// percorso del driver.
	Image   string
	Account string
	// ServiceDll è il file vero dei servizi ospitati da svchost.exe
	// (Parameters\ServiceDll o ServiceDll nella chiave del servizio).
	ServiceDll string
}

func isDriver(t uint32) bool {
	return t&(svcWin32Own|svcWin32Share) == 0 && t&(svcKernelDriver|svcFileSystemDriver|svcRecognizerDriver) != 0
}

// startName: boot | system | auto | delayed | manual | disabled.
func startName(start uint32, delayed bool) string {
	switch start {
	case 0:
		return "boot"
	case 1:
		return "system"
	case 2:
		if delayed {
			return "delayed"
		}
		return "auto"
	case 3:
		return "manual"
	case 4:
		return "disabled"
	}
	return ""
}

// accountOf riduce l'account di un servizio a una categoria, mai il nome:
// system | localservice | networkservice | user | other.
func accountOf(acc string) string {
	a := strings.ToLower(strings.TrimSpace(acc))
	switch a {
	case "", "localsystem", ".\\localsystem", "nt authority\\system", "system":
		return "system"
	case "nt authority\\localservice", "nt authority\\local service", "localservice":
		return "localservice"
	case "nt authority\\networkservice", "nt authority\\network service", "networkservice":
		return "networkservice"
	}
	if strings.HasPrefix(a, "nt service\\") || strings.HasPrefix(a, "nt authority\\") {
		// Account virtuali dei servizi e altri account di sistema.
		return "other"
	}
	return "user"
}

// perUserBase toglie dal nome di una copia di un servizio per utente il
// suffisso _LUID, che cambia a ogni accesso: due analisi dello stesso PC
// devono dare gli stessi nomi.
func perUserBase(name string, t uint32) string {
	if t&svcUserService == 0 {
		return name
	}
	i := strings.LastIndexByte(name, '_')
	if i <= 0 || i == len(name)-1 {
		return name
	}
	for _, c := range name[i+1:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return name
		}
	}
	return name[:i]
}

// mergeUserServices tiene una voce sola per ogni servizio per utente (il
// modello e le copie): in esecuzione se lo è almeno una copia.
func mergeUserServices(list []rawService) []rawService {
	var out []rawService
	at := map[string]int{}
	for _, s := range list {
		if s.Type&svcUserService == 0 {
			out = append(out, s)
			continue
		}
		base := perUserBase(s.Name, s.Type)
		s.Display = perUserBase(s.Display, s.Type)
		if i, ok := at[strings.ToLower(base)]; ok {
			out[i].Running = out[i].Running || s.Running
			// La configurazione del modello vale per tutte le copie.
			if s.Name == base {
				run := out[i].Running
				out[i] = s
				out[i].Running = run
			}
			continue
		}
		s.Name = base
		at[strings.ToLower(base)] = len(out)
		out = append(out, s)
	}
	return out
}

// serviceKey è la chiave del registro di un servizio, come la mostra
// Autoruns.
func serviceKey(name string) string {
	return `HKLM\System\CurrentControlSet\Services\` + name
}

// serviceItem prepara la voce di un servizio o di un driver: il file vero
// (ServiceDll per svchost, il .sys per i driver), il modo di avvio,
// l'account come categoria e il controllo del percorso senza virgolette.
func (rd reader) serviceItem(s rawService) item {
	drv := isDriver(s.Type)
	e := scan.AutorunEntry{Category: "services", Kind: "service", Name: s.Name, Location: serviceKey(s.Name)}
	if drv {
		e.Category, e.Kind = "drivers", "driver"
	}
	if d := strings.TrimSpace(s.Display); d != "" {
		e.Name = rd.cl.text(d)
	}
	e.Start = startName(s.Start, s.Delayed)
	e.Enabled = s.Start != 4
	e.Running = s.Running
	if !drv {
		if s.Type&svcUserService != 0 {
			e.Account = "user"
		} else {
			e.Account = accountOf(s.Account)
		}
	}
	it := item{entry: e}
	it.entry.Command = rd.cl.path(s.Image)
	image := strings.TrimSpace(s.Image)
	if image == "" {
		if drv {
			// Driver senza ImagePath: Windows lo carica da
			// System32\drivers\<nome>.sys (forma osservata, non documentata
			// nelle pagine lette).
			it.file = rd.res.Locate(`%SystemRoot%\System32\drivers\`+s.Name+".sys", false)
		}
		return it
	}
	file, args, quoted := rd.res.Split(image, false)
	it.file = rd.res.Locate(file, false)
	if strings.EqualFold(baseOf(file), "svchost.exe") && strings.TrimSpace(s.ServiceDll) != "" {
		it.file = rd.res.Locate(s.ServiceDll, false)
	} else if !drv {
		if target, proxy := ProxyTarget(file, args); proxy {
			if target == "" {
				it.interpreted = args != ""
			} else {
				it.target = rd.res.Locate(target, false)
			}
		}
	}
	if !drv && !quoted {
		// Percorso con spazi senza virgolette: CreateProcess prova prima i
		// prefissi (C:\Program.exe...). Grave solo se uno di quei file esiste.
		abs := rd.res.Locate(file, false)
		if strings.Contains(abs, " ") {
			it.entry.Unquoted = true
			for _, c := range InterceptorCandidates(abs) {
				if rd.res.exists(c) {
					it.entry.Interceptors++
				}
			}
			it.hijack = it.entry.Interceptors > 0
		}
	}
	return it
}
