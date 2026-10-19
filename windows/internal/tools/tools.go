// Package tools apre, solo su richiesta dell'utente, gli strumenti di
// Windows, i programmi di diagnostica più noti già installati e i loro siti
// ufficiali. Tutto passa da una lista bianca: dall'interfaccia arriva solo
// un identificativo, mai un percorso, un comando o un indirizzo.
//
// CrystalDiskInfo e CrystalDiskMark (open source, licenza MIT) sono inclusi
// nel pacchetto come copie originali e si avviano solo se l'eseguibile è
// quello del produttore (bundled.go). Gli altri programmi non sono inclusi:
// le loro licenze (CPU-Z, Malwarebytes...) non lo permettono o non lo rendono
// opportuno. Polaris li rileva se sono già installati e indica dove scaricarli.
package tools

import (
	"errors"
	"path/filepath"
	"strings"
)

// Windows è uno strumento integrato: un comando o un indirizzo ms-settings.
type Windows struct {
	File string
	Args string
}

// WindowsTools sono gli strumenti di Windows che l'interfaccia può aprire.
var WindowsTools = map[string]Windows{
	"windows-security":  {File: "windowsdefender:"},
	"windows-update":    {File: "ms-settings:windowsupdate"},
	"startup-apps":      {File: "ms-settings:startupapps"},
	"storage":           {File: "ms-settings:storagesense"},
	"power":             {File: "ms-settings:powersleep"},
	"recovery":          {File: "ms-settings:recovery"},
	"task-manager":      {File: "taskmgr.exe"},
	"resource-monitor":  {File: "resmon.exe"},
	"reliability":       {File: "perfmon.exe", Args: "/rel"},
	"event-viewer":      {File: "eventvwr.msc"},
	"device-manager":    {File: "devmgmt.msc"},
	"disk-management":   {File: "diskmgmt.msc"},
	"disk-cleanup":      {File: "cleanmgr.exe"},
	"defrag":            {File: "dfrgui.exe"},
	"memory-diagnostic": {File: "mdsched.exe"},
	"system-info":       {File: "msinfo32.exe"},
}

// Program è un programma di terze parti: sito ufficiale e, se si installa,
// come riconoscerlo tra i programmi installati.
type Program struct {
	Site string
	// Names sono parti del nome (in minuscolo) nelle voci di disinstallazione.
	Names []string
	// Exes sono gli unici eseguibili che Polaris accetta di avviare.
	Exes []string
}

// Programs sono i programmi della cassetta degli attrezzi. I siti sono stati
// verificati il 18 ottobre 2026.
var Programs = map[string]Program{
	"crystaldiskinfo":     {Site: "https://crystalmark.info/en/software/crystaldiskinfo/", Names: []string{"crystaldiskinfo"}, Exes: []string{"DiskInfo64.exe", "DiskInfo32.exe", "DiskInfoA64.exe", "DiskInfo.exe"}},
	"crystaldiskmark":     {Site: "https://crystalmark.info/en/software/crystaldiskmark/", Names: []string{"crystaldiskmark"}, Exes: []string{"DiskMark64.exe", "DiskMark32.exe", "DiskMarkA64.exe", "DiskMark.exe"}},
	"cpu-z":               {Site: "https://www.cpuid.com/softwares/cpu-z.html", Names: []string{"cpu-z"}, Exes: []string{"cpuz.exe", "cpuz_x64.exe", "cpuz_x32.exe"}},
	"hwinfo":              {Site: "https://www.hwinfo.com/", Names: []string{"hwinfo"}, Exes: []string{"HWiNFO64.exe", "HWiNFO32.exe", "HWiNFO.exe"}},
	"malwarebytes":        {Site: "https://www.malwarebytes.com/mwb-download", Names: []string{"malwarebytes"}, Exes: []string{"Malwarebytes.exe", "mbam.exe"}},
	"safety-scanner":      {Site: "https://learn.microsoft.com/it-it/defender-endpoint/safety-scanner-download"},
	"eset-online-scanner": {Site: "https://www.eset.com/int/home/online-scanner/"},
	"autoruns":            {Site: "https://learn.microsoft.com/it-it/sysinternals/downloads/autoruns"},
	"process-explorer":    {Site: "https://learn.microsoft.com/it-it/sysinternals/downloads/process-explorer"},
	"memtest86":           {Site: "https://www.memtest86.com/"},
	"wiztree":             {Site: "https://diskanalyzer.com/", Names: []string{"wiztree"}, Exes: []string{"WizTree64.exe", "WizTree.exe"}},
	"windirstat":          {Site: "https://windirstat.net/", Names: []string{"windirstat"}, Exes: []string{"windirstat.exe"}},
	"bluescreenview":      {Site: "https://www.nirsoft.net/utils/blue_screen_view.html", Names: []string{"bluescreenview"}, Exes: []string{"BlueScreenView.exe"}},
	"pc-health-check":     {Site: "https://support.microsoft.com/it-it/windows/come-usare-l-app-controllo-integrit%C3%A0-pc-9c8abd9b-03ba-4e67-81ef-36f37caa7844", Names: []string{"pc health check", "controllo integrità pc"}, Exes: []string{"PCHealthCheck.exe"}},
}

// Installed è un programma trovato tra quelli installati.
type Installed struct {
	Version string `json:"version,omitempty"`
	Path    string `json:"-"` // non esce dal PC: serve solo ad avviarlo
}

var (
	ErrUnknown      = errors.New("strumento sconosciuto")
	ErrNotInstalled = errors.New("il programma non risulta installato su questo PC: scaricalo dal sito ufficiale")
	ErrTarget       = errors.New("target deve essere app o site")
	ErrModified     = errors.New("la copia inclusa in Polaris risulta modificata o sostituita: per sicurezza non viene avviata. Riscarica il pacchetto di Polaris dalla fonte originale")
	ErrCancelled    = errors.New("avvio annullato: la richiesta dei permessi di amministratore non è stata confermata")
)

// Entry è una voce di disinstallazione del registro.
type Entry struct {
	Name, Version, Location, Icon string
}

// Detect riconosce i programmi del catalogo tra le voci di disinstallazione.
// Un programma conta come installato solo se uno degli eseguibili ammessi
// esiste davvero (exists), nella cartella di installazione o come icona.
func Detect(entries []Entry, exists func(string) bool) map[string]Installed {
	out := map[string]Installed{}
	for _, e := range entries {
		name := strings.ToLower(e.Name)
		for id, p := range Programs {
			if _, done := out[id]; done || len(p.Exes) == 0 || !matches(name, p.Names) {
				continue
			}
			if path := exeOf(e, p, exists); path != "" {
				out[id] = Installed{Version: strings.TrimSpace(e.Version), Path: path}
			}
		}
	}
	return out
}

func matches(name string, parts []string) bool {
	for _, p := range parts {
		if strings.Contains(name, p) {
			return true
		}
	}
	return false
}

// exeOf trova l'eseguibile: prima dall'icona (spesso è il programma stesso,
// con ",0" in coda), poi nella cartella di installazione.
func exeOf(e Entry, p Program, exists func(string) bool) string {
	allowed := func(path string) bool {
		base := filepath.Base(strings.ReplaceAll(path, `\`, "/"))
		for _, x := range p.Exes {
			if strings.EqualFold(base, x) {
				return true
			}
		}
		return false
	}
	icon := strings.Trim(strings.TrimSpace(e.Icon), `"`)
	if i := strings.LastIndex(icon, ","); i > 0 && !strings.Contains(icon[i:], `\`) {
		icon = strings.Trim(strings.TrimSpace(icon[:i]), `"`)
	}
	if icon != "" && allowed(icon) && exists(icon) {
		return icon
	}
	loc := strings.Trim(strings.TrimSpace(e.Location), `"`)
	if loc == "" {
		return ""
	}
	for _, x := range p.Exes {
		path := strings.TrimRight(loc, `\/`) + `\` + x
		if exists(path) {
			return path
		}
	}
	return ""
}

// Target dice che cosa aprire: un file da eseguire con i suoi argomenti e la
// cartella di lavoro, o un indirizzo web (url true).
type Target struct {
	File, Args, Dir string
	URL             bool
}

// Merge unisce i programmi installati e le copie incluse in Polaris, che hanno
// la precedenza perché sono verificate.
func Merge(installed map[string]Installed, bundled map[string]Included) map[string]Installed {
	out := make(map[string]Installed, len(installed)+len(bundled))
	for id, in := range installed {
		out[id] = in
	}
	for id, b := range bundled {
		if b.Path != "" {
			out[id] = Installed{Version: b.Version, Path: b.Path}
		}
	}
	return out
}

// Resolve traduce identificativo e destinazione (app o site) in ciò che va
// aperto, usando solo il catalogo e i programmi trovati (vedi Merge).
func Resolve(id, target string, installed map[string]Installed) (Target, error) {
	if w, ok := WindowsTools[id]; ok {
		if target != "app" {
			return Target{}, ErrTarget
		}
		return Target{File: w.File, Args: w.Args}, nil
	}
	p, ok := Programs[id]
	if !ok {
		return Target{}, ErrUnknown
	}
	switch target {
	case "site":
		return Target{File: p.Site, URL: true}, nil
	case "app":
		if in, ok := installed[id]; ok && in.Path != "" {
			return Target{File: in.Path, Dir: dirOf(in.Path)}, nil
		}
		return Target{}, ErrNotInstalled
	}
	return Target{}, ErrTarget
}

// dirOf è la cartella di un percorso Windows (anche nei test su altri sistemi).
func dirOf(path string) string {
	if i := strings.LastIndexAny(path, `\/`); i > 0 {
		return path[:i]
	}
	return ""
}
