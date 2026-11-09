package pcinfo

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"lanterna/internal/scan"
)

// Dispositivi e driver, come Gestione dispositivi: la lettura nativa sta in
// devices_windows.go (SetupAPI, Configuration Manager, registro dei servizi,
// NtQuerySystemInformation); qui la parte indipendente dal sistema, provata
// su qualunque piattaforma.

// rawDevice è un dispositivo presente come lo legge l'agente, prima della
// pulizia: non esce mai dal processo così com'è.
type rawDevice struct {
	Name        string
	Class       string
	Enumerator  string
	HardwareIDs []string
	Problem     int
	Status      uint32 // NTSTATUS che accompagna il problema
	Service     string
	Provider    string
	Version     string
	Date        string // AAAA-MM-GG
	Inf         string
	File        string // file del driver, dal registro dei servizi
}

// Codici di Gestione dispositivi usati qui (CM_PROB_* in cfg.h).
const (
	probDisabled = 22
)

// codeIntegrity* sono i bit di SYSTEM_CODEINTEGRITY_INFORMATION.
// CodeIntegrityOptions, dalla pagina di NtQuerySystemInformation (Microsoft
// Learn, winternl.h), che avverte che la funzione potrebbe cambiare.
const (
	codeIntegrityEnabled   = 0x01
	codeIntegrityTestSign  = 0x02
	codeIntegrityDebugMode = 0x80
	codeIntegrityHVCI      = 0x400
)

// CodeIntegrityOf interpreta i bit di CodeIntegrityOptions.
func CodeIntegrityOf(options uint32) *scan.CodeIntegrity {
	return &scan.CodeIntegrity{
		Options:     options,
		Enabled:     options&codeIntegrityEnabled != 0,
		TestSigning: options&codeIntegrityTestSign != 0,
		DebugMode:   options&codeIntegrityDebugMode != 0,
		HVCI:        options&codeIntegrityHVCI != 0,
	}
}

// hwToken sono le parti di un hardware ID che identificano produttore,
// modello e revisione: tutto il resto (nomi di modello liberi, indirizzi
// Bluetooth negli ID dei dispositivi abbinati) viene scartato.
var hwToken = []*regexp.Regexp{
	regexp.MustCompile(`^(VEN|VID)_[0-9A-Z]{3,4}$`),
	regexp.MustCompile(`^(DEV|PID)_[0-9A-F]{4}$`),
	regexp.MustCompile(`^SUBSYS_[0-9A-F]{8}$`),
	regexp.MustCompile(`^REV_[0-9A-F]{2,4}$`),
	regexp.MustCompile(`^MI_[0-9A-F]{2}$`),
	regexp.MustCompile(`^CC_[0-9A-F]{2,6}$`),
	regexp.MustCompile(`^COL[0-9A-F]{2}$`),
	// Identificativi PNP e ACPI: tre lettere più quattro cifre esadecimali
	// (PNP0A08, INT33A0, DELA0B2) o quattro più quattro (ACPI0003).
	regexp.MustCompile(`^[A-Z]{3,4}[0-9A-F]{4}$`),
}

var hwEnumerator = regexp.MustCompile(`^[A-Z0-9_]{1,24}$`)

// SanitizeHardwareID riduce un hardware ID alle parti che non identificano
// l'esemplare: il bus e i codici di produttore, modello e revisione. Gli
// identificativi d'istanza (con numeri di serie e indirizzi MAC) non passano
// mai di qui: l'agente non li legge.
func SanitizeHardwareID(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	enum, rest, ok := strings.Cut(id, `\`)
	if !ok || !hwEnumerator.MatchString(enum) {
		return ""
	}
	var keep []string
	for _, part := range strings.FieldsFunc(rest, func(r rune) bool { return r == '&' || r == '\\' }) {
		for _, re := range hwToken {
			if re.MatchString(part) {
				keep = append(keep, part)
				break
			}
		}
	}
	if len(keep) == 0 {
		return enum
	}
	return enum + `\` + strings.Join(keep, "&")
}

// privateEnumerators sono i bus dei dispositivi che portano spesso un nome
// scelto dall'utente o il nome di un altro computer: dispositivi Bluetooth
// abbinati, dispositivi di rete (UPnP, WSD), code di stampa.
var privateEnumerators = map[string]bool{
	"BTHENUM": true, "BTHLE": true, "BTHLEDEVICE": true, "BTHHFENUM": true,
	"SWD": true, "UMB": true, "WSDPRINT": true, "PRINTENUM": true,
}

// privateClasses sono le classi con nomi scelti dall'utente (telefoni,
// stampanti condivise, scanner di rete).
var privateClasses = map[string]bool{
	"WPD": true, "PRINTER": true, "PRINTQUEUE": true, "IMAGE": true, "BLUETOOTH": true,
}

// classLabel dà il nome generico che sostituisce un nome privato.
var classLabel = map[string]string{
	"WPD": "Dispositivo portatile", "PRINTER": "Stampante", "PRINTQUEUE": "Coda di stampa",
	"IMAGE": "Scanner o fotocamera", "BLUETOOTH": "Dispositivo Bluetooth", "MEDIA": "Dispositivo audio",
	"HIDCLASS": "Dispositivo di input", "KEYBOARD": "Tastiera", "MOUSE": "Mouse", "NET": "Scheda di rete",
	"DISPLAY": "Scheda video", "MONITOR": "Schermo", "SOFTWAREDEVICE": "Dispositivo software",
	"AUDIOENDPOINT": "Uscita o ingresso audio", "CAMERA": "Fotocamera",
}

// DeviceName restituisce il nome da mostrare: quello di Windows, se descrive
// il prodotto; un nome generico se il dispositivo può portare un nome scelto
// dall'utente o quello di un altro computer.
func DeviceName(name, class, enumerator string) string {
	name = strings.Join(strings.Fields(name), " ")
	if r := []rune(name); len(r) > 120 {
		name = string(r[:120])
	}
	uc, ue := strings.ToUpper(class), strings.ToUpper(enumerator)
	if name != "" && !privateEnumerators[ue] && !privateClasses[uc] && !strings.Contains(name, `\\`) {
		return name
	}
	// I controller e le radio Bluetooth (sul bus USB o PCI) hanno il nome del
	// prodotto, non quello di un dispositivo abbinato.
	if uc == "BLUETOOTH" && (ue == "USB" || ue == "PCI") && name != "" && !strings.Contains(name, `\\`) {
		return name
	}
	if l := classLabel[uc]; l != "" {
		return l
	}
	if ue == "BTHENUM" || ue == "BTHLE" || ue == "BTHLEDEVICE" || ue == "BTHHFENUM" {
		return "Dispositivo Bluetooth"
	}
	if name == "" && uc == "" {
		// Senza driver Windows non conosce né il nome né la classe: Gestione
		// dispositivi lo mostra così, tra gli altri dispositivi.
		return "Dispositivo sconosciuto"
	}
	return "Dispositivo"
}

var oemInf = regexp.MustCompile(`(?i)^oem[0-9]{1,4}\.inf$`)

// IsInboxInf dice se il file INF è di Windows: i pacchetti di terze parti
// vengono copiati come oemNNN.inf, quelli inclusi in Windows tengono il nome.
func IsInboxInf(inf string) bool {
	return inf != "" && !oemInf.MatchString(strings.TrimSpace(inf))
}

// baseName restituisce l'ultima parte di un percorso di Windows anche fuori
// da Windows (filepath.Base qui non conosce le barre rovesciate).
func baseName(p string) string {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, `"`) {
		// Percorso tra virgolette, eventualmente seguito da argomenti.
		p = p[1:]
		if i := strings.IndexByte(p, '"'); i >= 0 {
			p = p[:i]
		}
	} else if m := exeArgs.FindStringIndex(p); m != nil {
		p = p[:m[1]-1] // percorso senza virgolette seguito da argomenti
	}
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSpace(p)
}

var exeArgs = regexp.MustCompile(`(?i)\.(exe|sys|dll) `)

// DriverFile ricava il nome del file del driver dal valore ImagePath della
// chiave del servizio. Senza ImagePath un driver si trova di norma in
// System32\drivers con il nome del servizio: comportamento noto ma non
// documentato, usato solo per i driver in kernel.
func DriverFile(imagePath, service string, kernel bool) string {
	if f := baseName(imagePath); f != "" {
		if !strings.Contains(f, ".") {
			return ""
		}
		return strings.ToLower(f)
	}
	if kernel && service != "" {
		return strings.ToLower(service) + ".sys"
	}
	return ""
}

// NTStatusHex scrive un NTSTATUS come lo mostra Windows ("0xC0000034").
func NTStatusHex(s uint32) string {
	if s == 0 {
		return ""
	}
	return fmt.Sprintf("0x%08X", s)
}

// Decodifica dei valori delle proprietà dei dispositivi (DEVPROPTYPE).

func propString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	return strings.TrimSpace(string(utf16.Decode(u)))
}

func propStringList(b []byte) []string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	var out []string
	start := 0
	for i, c := range u {
		if c == 0 {
			if i > start {
				out = append(out, string(utf16.Decode(u[start:i])))
			}
			start = i + 1
		}
	}
	return out
}

func propUint32(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}

// filetimeDate converte la data di un driver (FILETIME) in AAAA-MM-GG. La
// data del pacchetto è un giorno senza ora: con mezza giornata in più la
// conversione non cambia giorno anche se Windows l'ha salvata come mezzanotte
// di un altro fuso orario.
func filetimeDate(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	ft := int64(binary.LittleEndian.Uint64(b))
	if ft <= 0 {
		return ""
	}
	const epoch = 116444736000000000 // 1601-01-01 → 1970-01-01, in unità da 100 ns
	t := time.Unix(0, (ft-epoch)*100).UTC().Add(12 * time.Hour)
	if t.Year() < 1990 || t.Year() > 2200 {
		return ""
	}
	return t.Format("2006-01-02")
}

// BuildDevices prepara lo stato dei dispositivi da esportare: conta tutti i
// dispositivi presenti e tiene quelli con un problema, quelli con un driver
// di terze parti e quelli il cui file compare tra i driver indicati dalle
// schermate blu (suspects, nomi di file in minuscolo).
func BuildDevices(raw []rawDevice, suspects map[string]bool) *scan.DevicesData {
	d := &scan.DevicesData{Items: []scan.DeviceInfo{}}
	classes := map[string]*scan.DeviceClassCount{}
	for _, r := range raw {
		d.Total++
		class := strings.TrimSpace(r.Class)
		key := class
		if key == "" {
			key = "?"
		}
		c := classes[key]
		if c == nil {
			c = &scan.DeviceClassCount{Class: class}
			classes[key] = c
		}
		c.Count++
		if r.Problem != 0 {
			d.Problems++
			c.Problems++
		}
		inbox := IsInboxInf(r.Inf)
		file := strings.ToLower(r.File)
		if r.Problem == 0 && (inbox || r.Inf == "") && !(file != "" && suspects[file]) {
			continue
		}
		info := scan.DeviceInfo{
			Name:       DeviceName(r.Name, class, r.Enumerator),
			Class:      class,
			Enumerator: strings.ToUpper(r.Enumerator),
			Problem:    r.Problem,
			Service:    r.Service,
		}
		for _, h := range r.HardwareIDs {
			if s := SanitizeHardwareID(h); s != "" {
				info.HardwareID = s
				break
			}
		}
		if r.Problem != 0 {
			info.ProblemStatus = NTStatusHex(r.Status)
		}
		if r.Inf != "" || r.Provider != "" || r.Version != "" || file != "" {
			info.Driver = &scan.DriverInfo{
				Provider: strings.TrimSpace(r.Provider), Version: strings.TrimSpace(r.Version), Date: r.Date,
				Inf: strings.ToLower(strings.TrimSpace(r.Inf)), Inbox: inbox, File: file,
			}
		}
		d.Items = append(d.Items, info)
	}
	for _, c := range classes {
		d.Classes = append(d.Classes, *c)
	}
	sort.Slice(d.Classes, func(i, j int) bool {
		a, b := d.Classes[i], d.Classes[j]
		if a.Problems != b.Problems {
			return a.Problems > b.Problems
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Class < b.Class
	})
	// Prima i problemi (i disattivati dopo), poi i driver di terze parti per classe e nome.
	rank := func(x scan.DeviceInfo) int {
		switch {
		case x.Problem != 0 && x.Problem != probDisabled:
			return 0
		case x.Problem == probDisabled:
			return 1
		}
		return 2
	}
	sort.SliceStable(d.Items, func(i, j int) bool {
		a, b := d.Items[i], d.Items[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		return a.Name < b.Name
	})
	return d
}

// CrashSuspects raccoglie i file dei driver indicati come probabile causa
// nelle schermate blu lette (in minuscolo).
func CrashSuspects(c *scan.CrashData) map[string]bool {
	out := map[string]bool{}
	if c == nil {
		return out
	}
	add := func(d *scan.CrashDump) {
		if d != nil && d.Probable != nil && d.Probable.Driver != "" {
			out[strings.ToLower(baseName(d.Probable.Driver))] = true
		}
	}
	for i := range c.Dumps {
		add(&c.Dumps[i])
	}
	add(c.MemoryDump)
	return out
}
