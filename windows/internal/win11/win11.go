// Package win11 confronta il processore del PC con l'elenco ufficiale dei
// processori supportati da Windows 11, su richiesta dell'utente.
//
// Polaris non incorpora gli elenchi: le pagine di Microsoft Learn non hanno
// una licenza che ne consenta la copia (Condizioni d'uso di Microsoft
// Learn). Il PC dell'utente scarica la pagina, come farebbe il browser, la
// legge in memoria e la scarta: si conservano solo l'esito, la riga che
// corrisponde e il numero di righe. Nulla si salva su disco.
//
// Gli elenchi sono scritti per i produttori di PC nuovi e cambiano a ogni
// versione; Microsoft considera supportate anche le generazioni uscite dopo
// l'elenco, e il controllo vero di Windows Update guarda famiglia, modello e
// stepping del processore, non il nome. Per questo l'esito è «nell'elenco»,
// «non nell'elenco» o «da verificare», mai «non supportato».
package win11

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"lanterna/internal/scan"
)

// Host è il solo sito da cui si scaricano gli elenchi, anche dopo i rimandi.
const Host = "learn.microsoft.com"

const base = "https://" + Host + "/en-us/windows-hardware/design/minimum/supported/"

// List è un elenco ufficiale dei processori supportati.
type List struct {
	Vendor  string // intel | amd | qualcomm
	Version string // versione di Windows 11 dell'elenco
	Kind    string // model (per modello) | series (per serie)
	URL     string
}

// Lists sono gli elenchi più recenti per produttore (verificati il 17
// novembre 2026): per AMD l'ultimo per modello (24H2; il 25H2 è solo per
// serie e con eccezioni non spiegate), per Intel e Qualcomm il 25H2, che
// Microsoft pubblica solo per serie.
var Lists = map[string]List{
	"amd":      {Vendor: "amd", Version: "24H2", Kind: "model", URL: base + "windows-11-24h2-supported-amd-processors"},
	"intel":    {Vendor: "intel", Version: "25H2", Kind: "series", URL: base + "windows-11-25h2-supported-intel-processors"},
	"qualcomm": {Vendor: "qualcomm", Version: "25H2", Kind: "series", URL: base + "windows-11-25h2-supported-qualcomm-processors"},
}

// VendorOf riconosce il produttore dal VendorIdentifier del registro
// (GenuineIntel, AuthenticAMD) o, se manca, dal nome del processore.
func VendorOf(vendorID, name string) string {
	v, n := strings.ToLower(vendorID), strings.ToLower(name)
	switch {
	case strings.Contains(v, "genuineintel"), strings.Contains(v, "intel"):
		return "intel"
	case strings.Contains(v, "authenticamd"), strings.Contains(v, "amd"):
		return "amd"
	case strings.Contains(v, "qualcomm"), strings.Contains(n, "snapdragon"), strings.Contains(n, "qualcomm"):
		return "qualcomm"
	case strings.Contains(n, "intel"):
		return "intel"
	case strings.HasPrefix(n, "amd ") || strings.Contains(n, "ryzen") || strings.Contains(n, "athlon") || strings.Contains(n, "epyc"):
		return "amd"
	}
	return ""
}

// ---------------------------------------------------------------- pagina

// maxPage limita la pagina scaricata (quella AMD pesa qualche centinaio di KB).
const maxPage = 6 << 20

// Options configura il controllo.
type Options struct {
	// Transport passa dal proxy di sistema, come i download della cassetta.
	Transport http.RoundTripper
	UserAgent string
	// CPU e Vendor sono il nome del processore (ProcessorNameString) e il
	// suo VendorIdentifier.
	CPU, Vendor string
	Now         func() time.Time
	// Hosts e URL sostituiscono l'host ammesso e l'indirizzo dell'elenco:
	// solo per le prove.
	Hosts []string
	URL   string
}

var (
	errHost   = errors.New("la pagina è passata da un sito diverso da learn.microsoft.com e non è stata letta")
	errFormat = errors.New("la pagina di Microsoft non ha la tabella attesa: forse è cambiato il formato")
)

func allowed(u *url.URL, hosts []string) error {
	if u.Scheme != "https" {
		return errHost
	}
	h := strings.ToLower(u.Hostname())
	for _, a := range hosts {
		if h == a {
			return nil
		}
	}
	return errHost
}

// fetch scarica la pagina, solo in https e solo dagli host ammessi, con un
// limite di dimensione.
func fetch(ctx context.Context, opt Options, raw string) (string, error) {
	hosts := opt.Hosts
	if len(hosts) == 0 {
		hosts = []string{Host}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if err := allowed(u, hosts); err != nil {
		return "", err
	}
	tr := opt.Transport
	if tr == nil {
		tr = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("troppi reindirizzamenti")
			}
			return allowed(req.URL, hosts)
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "text/html")
	if opt.UserAgent != "" {
		req.Header.Set("User-Agent", opt.UserAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errHost) {
			return "", errHost
		}
		if ctx.Err() != nil {
			return "", errors.New("learn.microsoft.com non ha risposto in tempo")
		}
		return "", fmt.Errorf("learn.microsoft.com non raggiungibile: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("learn.microsoft.com ha risposto %d", resp.StatusCode)
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); ct != "" && !strings.HasPrefix(ct, "text/html") {
		return "", fmt.Errorf("learn.microsoft.com ha risposto con un contenuto inatteso (%s)", ct)
	}
	if resp.ContentLength > maxPage {
		return "", errors.New("la pagina di Microsoft è più grande del previsto e non è stata letta")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxPage+1))
	if err != nil {
		return "", fmt.Errorf("lettura della pagina interrotta: %w", err)
	}
	if len(b) > maxPage {
		return "", errors.New("la pagina di Microsoft è più grande del previsto e non è stata letta")
	}
	return string(b), nil
}

// Check scarica l'elenco del produttore del processore e lo confronta con
// il nome del processore. Non restituisce mai nil: un errore finisce in
// Error con l'esito «unknown».
func Check(ctx context.Context, opt Options) *scan.Win11CPUCheck {
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	cpu := strings.Join(strings.Fields(opt.CPU), " ")
	res := &scan.Win11CPUCheck{At: now().UTC().Format(time.RFC3339), Kind: "series", Result: "unknown", CPU: cpu}
	l, ok := Lists[VendorOf(opt.Vendor, cpu)]
	if !ok {
		res.Error = "produttore del processore non riconosciuto: Microsoft pubblica elenchi solo per Intel, AMD e Qualcomm"
		return res
	}
	res.Source, res.Version, res.Kind = l.URL, l.Version, l.Kind
	if opt.URL != "" {
		res.Source = opt.URL
	}
	page, err := fetch(ctx, opt, res.Source)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	header, rows := ParseTable(page)
	if err := checkHeader(l, header); err != nil || len(rows) == 0 {
		res.Error = errFormat.Error()
		return res
	}
	res.Rows = len(rows)
	res.Result, res.Match = Compare(l, header, rows, cpu)
	return res
}

func checkHeader(l List, header []string) error {
	need := []string{"series"}
	if l.Kind == "model" {
		need = []string{"brand", "model"}
	}
	for _, n := range need {
		if column(header, n) < 0 {
			return errFormat
		}
	}
	return nil
}

func column(header []string, name string) int {
	for i, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			return i
		}
	}
	return -1
}

// ------------------------------------------------------- tabella HTML

// ParseTable estrae dalla pagina la prima tabella la cui intestazione
// comprende «Manufacturer»: l'intestazione e le righe di dati, con il testo
// di ogni cella senza tag, entità e spazi in più. Basta un lettore minimo:
// righe e celle, senza tabelle annidate.
func ParseTable(page string) (header []string, rows [][]string) {
	for _, t := range parseTables(page) {
		if len(t) == 0 || column(t[0], "manufacturer") < 0 {
			continue
		}
		for _, r := range t[1:] {
			if len(r) == len(t[0]) {
				rows = append(rows, r)
			}
		}
		return t[0], rows
	}
	return nil, nil
}

// parseTables legge tutte le tabelle della pagina: per ognuna le righe e,
// per ogni riga, il testo delle celle (th o td).
func parseTables(s string) [][][]string {
	var tables [][][]string
	var cur [][]string
	var row []string
	var cell strings.Builder
	depth, inRow, inCell := 0, false, false
	endCell := func() {
		if inCell {
			row = append(row, cleanCell(cell.String()))
			cell.Reset()
			inCell = false
		}
	}
	endRow := func() {
		endCell()
		if inRow {
			if len(row) > 0 {
				cur = append(cur, row)
			}
			row, inRow = nil, false
		}
	}
	for i := 0; i < len(s); {
		j := strings.IndexByte(s[i:], '<')
		if j < 0 {
			if inCell {
				cell.WriteString(s[i:])
			}
			break
		}
		if inCell {
			cell.WriteString(s[i : i+j])
		}
		i += j
		if strings.HasPrefix(s[i:], "<!--") {
			k := strings.Index(s[i+4:], "-->")
			if k < 0 {
				break
			}
			i += 4 + k + 3
			continue
		}
		k := strings.IndexByte(s[i:], '>')
		if k < 0 {
			break
		}
		name, closing := tagName(s[i+1 : i+k])
		i += k + 1
		switch name {
		case "script", "style", "sup":
			// Contenuto da non leggere (i rimandi alle note in <sup>
			// finirebbero attaccati al modello).
			if !closing {
				if end := indexFold(s[i:], "</"+name); end >= 0 {
					i += end
				} else {
					i = len(s)
				}
			}
		case "table":
			if !closing {
				depth++
				if depth == 1 {
					cur = nil
				}
			} else if depth > 0 {
				depth--
				if depth == 0 {
					endRow()
					tables = append(tables, cur)
				}
			}
		case "tr":
			if depth == 1 {
				endRow()
				inRow = !closing
			}
		case "td", "th":
			if depth == 1 && inRow {
				endCell()
				inCell = !closing
			}
		case "br", "p", "div", "li":
			if inCell {
				cell.WriteByte(' ')
			}
		}
	}
	return tables
}

// tagName restituisce il nome di un tag in minuscolo e se è di chiusura.
func tagName(tag string) (string, bool) {
	tag = strings.TrimSpace(tag)
	closing := strings.HasPrefix(tag, "/")
	tag = strings.TrimPrefix(tag, "/")
	end := strings.IndexAny(tag, " \t\r\n/")
	if end >= 0 {
		tag = tag[:end]
	}
	return strings.ToLower(tag), closing
}

func indexFold(s, sub string) int {
	return strings.Index(strings.ToLower(s), sub)
}

// cleanCell toglie le entità, gli spazi a larghezza zero e gli spazi in più.
func cleanCell(s string) string {
	s = html.UnescapeString(s)
	s = strings.NewReplacer("\u200b", "", "\ufeff", "", "\u00ad", "").Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

// ------------------------------------------------------------ confronto

// Compare cerca il processore nelle righe dell'elenco: listed (nell'elenco),
// notListed (il nome si interpreta ma non c'è), unknown (il nome non si
// interpreta, oppure la serie dell'elenco comprende anche processori più
// vecchi non supportati e decide il modello: da verificare con Controllo
// integrità PC). match è la riga trovata.
func Compare(l List, header []string, rows [][]string, cpu string) (result, match string) {
	if virtualCPU.MatchString(cpu) {
		return "unknown", ""
	}
	switch l.Vendor {
	case "amd":
		key := AMDNameKey(cpu)
		if key == "" {
			return "unknown", ""
		}
		b, m := column(header, "brand"), column(header, "model")
		for _, r := range rows {
			if AMDRowKey(r[b], r[m]) == key {
				return "listed", rowLabel(r[b], r[m])
			}
		}
		return "notListed", ""
	case "intel", "qualcomm":
		var cands []string
		if l.Vendor == "intel" {
			cands = IntelSeries(cpu)
		} else if s := QualcommSeries(cpu); s != "" {
			cands = []string{s}
		}
		if len(cands) == 0 {
			return "unknown", ""
		}
		c := column(header, "series")
		for _, want := range cands {
			for _, r := range rows {
				if normSeries(r[c]) == want {
					if tooWide[want] {
						return "unknown", cleanName(r[c])
					}
					return "listed", cleanName(r[c])
				}
			}
		}
		return "notListed", ""
	}
	return "unknown", ""
}

// virtualCPU riconosce i processori virtuali delle macchine virtuali: il
// processore vero è quello del computer che le ospita.
var virtualCPU = regexp.MustCompile(`(?i)\b(virtual|qemu|kvm|hyper-v|vmware|bochs)\b`)

// rowLabel è la riga trovata in forma leggibile ("Ryzen 7 PRO 4750U").
func rowLabel(brand, model string) string {
	b := cleanName(brand)
	if strings.EqualFold(b, "AMD") {
		b = ""
	}
	return strings.TrimSpace(b + " " + cleanName(model))
}

// marks toglie marchi registrati, spazi a larghezza zero e simili.
var marks = strings.NewReplacer("™", "", "®", "", "©", "", "\u200b", "", "\ufeff", "", "(R)", "", "(r)", "", "(TM)", "", "(tm)", "", "(Tm)", "")

func cleanName(s string) string {
	return strings.Join(strings.Fields(marks.Replace(s)), " ")
}

// normSeries è la forma di confronto di una serie dell'elenco.
func normSeries(s string) string { return strings.ToLower(cleanName(s)) }

// ------------------------------------------------------------------ AMD

var (
	amdModelTail = regexp.MustCompile(`(?i)\s*\(OEM Only\)|\s+with Radeon.*$|\s+Microsoft Surface Edition$|\s+Processor$`)
	amdBrandTail = regexp.MustCompile(`(?i)\s+\S+\s+Series$`)
	amdNameTail  = regexp.MustCompile(`(?i)\s+(with|w/)\s+Radeon.*$|\s+(\d+|[a-z]+)-Cores?(\s+Processor)?$|\s+Processor$|\s+Microsoft Surface.*$`)
	amdFreq      = regexp.MustCompile(`\s*@.*$`)
	amdPrefix    = regexp.MustCompile(`(?i)^AMD\s+`)
)

// AMDRowKey è la chiave di una riga dell'elenco AMD: marca e modello senza
// il marchio «AMD», le note tra parentesi e le code descrittive
// ("Ryzen™ 7 PRO" + "4750U" → "ryzen 7 pro 4750u"; "Ryzen Embedded R2000
// Series" + "R2314" → "ryzen embedded r2314").
func AMDRowKey(brand, model string) string {
	b, m := cleanName(brand), cleanName(model)
	m = strings.TrimSpace(amdModelTail.ReplaceAllString(m, ""))
	if strings.EqualFold(b, "AMD") {
		b = ""
	}
	b = amdBrandTail.ReplaceAllString(b, "")
	return strings.ToLower(strings.TrimSpace(b + " " + m))
}

// AMDNameKey è la chiave del nome del processore come lo scrive Windows
// ("AMD Ryzen 5 3500U with Radeon Vega Mobile Gfx" → "ryzen 5 3500u";
// "AMD Ryzen 7 1700 Eight-Core Processor" → "ryzen 7 1700"); "" se il nome
// non è quello di un processore AMD riconoscibile.
func AMDNameKey(name string) string {
	n := cleanName(name)
	n = amdFreq.ReplaceAllString(n, "")
	n = amdPrefix.ReplaceAllString(n, "")
	n = strings.TrimSpace(amdNameTail.ReplaceAllString(n, ""))
	// Ogni modello AMD ha un numero: senza, il nome non si interpreta.
	if !strings.ContainsAny(n, "0123456789") {
		return ""
	}
	return strings.ToLower(n)
}

// ---------------------------------------------------------------- Intel

// tooWide sono le serie dell'elenco che comprendono anche modelli di
// generazioni non supportate (Celeron 3865U e Pentium 4415U sono Kaby Lake,
// Core i5-7640X è Kaby Lake-X): l'esito dipende dal modello, da verificare.
var tooWide = map[string]bool{
	"celeron 3000 series":       true,
	"pentium gold 4000u series": true,
	"pentium gold 4000y series": true,
	"intel core 7000x series":   true,
}

var (
	intelFreq   = regexp.MustCompile(`(?i)\s*@.*$`)
	intelCPU    = regexp.MustCompile(`(?i)\bCPU\b`)
	intelVendor = regexp.MustCompile(`(?i)^(Genuine )?Intel\s+`)
	intelGen    = regexp.MustCompile(`(?i)^(\d+)(st|nd|rd|th) Gen\s+`)
	intelCoreI  = regexp.MustCompile(`(?i)\bCore i([3579])-(\d{3,5})([A-Z]{0,3})\d?\b`)
	intelCoreN  = regexp.MustCompile(`(?i)\bCore i3-N3\d\d\b`)
	intelCoreM  = regexp.MustCompile(`(?i)\bCore m[357]-(\d)`)
	intelUltra  = regexp.MustCompile(`(?i)\bCore Ultra X?[3579] (\d)\d\d[A-Z]*\b`)
	intelCore   = regexp.MustCompile(`(?i)\bCore ([3579]) (\d)\d\d[A-Z]*\b`)
	intelNSer   = regexp.MustCompile(`(?i)^(?:Processor )?N(\d)(\d{1,2})$`)
	intelU300   = regexp.MustCompile(`(?i)^(?:Processor )?U300E?$`)
	intel300    = regexp.MustCompile(`(?i)^(?:Processor )?300T?$`)
	intelAtom   = regexp.MustCompile(`(?i)\bAtom x(\d)\d{3}[A-Z]*\b`)
	intelPentCe = regexp.MustCompile(`(?i)\b(Pentium|Celeron)(?: (Gold|Silver))?(?: Processor)? ([GJN]?)(\d)(\d)\d\d([A-Z]*)\b`)
	intelXeonSc = regexp.MustCompile(`(?i)\bXeon (?:Bronze|Silver|Gold|Platinum) \d(\d)\d\d[A-Z+]*`)
	intelXeonWn = regexp.MustCompile(`(?i)\bXeon w[3579]-(\d)(\d)\d\d[A-Z]*\b`)
	intelXeonW  = regexp.MustCompile(`(?i)\bXeon W-(\d{4,5})(M?)`)
	intelXeonDE = regexp.MustCompile(`(?i)\bXeon ([DE])-(\d)(\d)\d\d`)
	intelXeonE3 = regexp.MustCompile(`(?i)\bXeon E([357])-(\d)(\d)\d\d`)
	intelXeon6  = regexp.MustCompile(`(?i)\bXeon (6)\d\d[A-Z]?$`)
)

func ordinal(n int) string {
	s := strconv.Itoa(n)
	if n%100 >= 11 && n%100 <= 13 {
		return s + "th"
	}
	switch n % 10 {
	case 1:
		return s + "st"
	case 2:
		return s + "nd"
	case 3:
		return s + "rd"
	}
	return s + "th"
}

// IntelSeries trasforma il nome di un processore Intel nelle serie con cui
// lo scrive l'elenco di Microsoft (in minuscolo, dalla più precisa), con
// regole esplicite: la generazione dal numero del modello per i Core i, la
// serie per Core Ultra e Core, la prima cifra per Pentium e Celeron, la
// seconda per gli Xeon Scalable. nil se il nome non si interpreta.
func IntelSeries(name string) []string {
	n := cleanName(name)
	n = intelFreq.ReplaceAllString(n, "")
	n = intelCPU.ReplaceAllString(n, " ")
	n = strings.Join(strings.Fields(n), " ")
	n = intelGen.ReplaceAllString(n, "")
	n = intelVendor.ReplaceAllString(n, "")
	switch {
	case intelCoreN.MatchString(n):
		return []string{"core processor n300 series"}
	case intelCoreI.MatchString(n):
		m := intelCoreI.FindStringSubmatch(n)
		k, num, suf := m[1], m[2], strings.ToUpper(m[3])
		var gen int
		switch {
		case len(num) == 5 || len(num) == 4 && num[0] == '1':
			gen, _ = strconv.Atoi(num[:2])
		case len(num) == 4:
			gen = int(num[0] - '0')
		default:
			gen = 1
		}
		if (suf == "X" || suf == "XE") && (k == "7" || k == "9" || k == "5") {
			if len(num) == 5 {
				return []string{"intel core 10000x series"}
			}
			return []string{"intel core " + num[:1] + "000x series"}
		}
		if gen == 14 {
			return []string{"core i" + k + " processors (14th generation)"}
		}
		return []string{ordinal(gen) + " generation core i" + k + " processors"}
	case intelCoreM.MatchString(n):
		g, _ := strconv.Atoi(intelCoreM.FindStringSubmatch(n)[1])
		return []string{ordinal(g) + " generation core m processors"}
	case intelUltra.MatchString(n):
		return []string{"core ultra processors (series " + intelUltra.FindStringSubmatch(n)[1] + ")"}
	case intelCore.MatchString(n):
		return []string{"core processors (series " + intelCore.FindStringSubmatch(n)[2] + ")"}
	case intelNSer.MatchString(n):
		m := intelNSer.FindStringSubmatch(n)
		return []string{"n" + m[1] + strings.Repeat("0", len(m[2])) + " series"}
	case intelU300.MatchString(n):
		return []string{"u300 series"}
	case intel300.MatchString(n):
		return []string{"intel 300 processor for desktop"}
	case intelAtom.MatchString(n):
		return []string{"atom x" + intelAtom.FindStringSubmatch(n)[1] + "000 series"}
	case intelPentCe.MatchString(n):
		m := intelPentCe.FindStringSubmatch(n)
		fam, tier, let, d1, d2, suf := strings.ToLower(m[1]), strings.ToLower(m[2]), strings.ToUpper(m[3]), m[4], m[5], strings.ToLower(m[6])
		if fam == "celeron" {
			return []string{"celeron " + strings.ToLower(let) + d1 + "000 series"}
		}
		if tier == "" {
			switch {
			case let == "J" || let == "N":
				tier = "silver"
			case let == "" && d1 == "6" && d2 == "8":
				return []string{"pentium 6800 series"}
			default:
				tier = "gold"
			}
		}
		s := "pentium " + tier + " " + strings.ToLower(let) + d1 + "000"
		if tier == "gold" && (suf == "u" || suf == "y") {
			return []string{s + suf + " series", s + " series"}
		}
		return []string{s + " series"}
	case intelXeonSc.MatchString(n):
		g, _ := strconv.Atoi(intelXeonSc.FindStringSubmatch(n)[1])
		if g == 1 {
			return []string{"xeon scalable processors"}
		}
		return []string{ordinal(g) + " generation xeon scalable processors"}
	case intelXeonWn.MatchString(n):
		m := intelXeonWn.FindStringSubmatch(n)
		return []string{"xeon w-" + m[1] + m[2] + "00 series"}
	case intelXeonW.MatchString(n):
		m := intelXeonW.FindStringSubmatch(n)
		num, mobile := m[1], m[2] != ""
		if mobile && len(num) == 5 {
			return []string{"xeon w-" + num[:2] + "000m series"}
		}
		if len(num) == 4 {
			return []string{"xeon w-" + num[:2] + "00 series"}
		}
		return nil
	case intelXeonE3.MatchString(n):
		m := intelXeonE3.FindStringSubmatch(n)
		return []string{"xeon e" + m[1] + "-" + m[2] + m[3] + "00 series"}
	case intelXeonDE.MatchString(n):
		m := intelXeonDE.FindStringSubmatch(n)
		return []string{"xeon " + strings.ToLower(m[1]) + "-" + m[2] + m[3] + "00 series"}
	case intelXeon6.MatchString(n):
		return []string{"xeon 600 processors for workstation"}
	}
	return nil
}

// ------------------------------------------------------------- Qualcomm

var (
	qcModel = regexp.MustCompile(`(?i)\bX([12])([EP]?)[- ]?\d{2}[- ]?\d{3}\b`)
	qcWords = regexp.MustCompile(`(?i)\bSnapdragon X(2)? (Elite|Plus)\b`)
)

// QualcommSeries ricava la serie dell'elenco 25H2 (X1, X1P, X1E, X2P, X2E)
// dal codice del modello ("X1E-78-100", "X1E78100") o dal nome commerciale
// ("Snapdragon X Elite"); "" per gli altri Snapdragon, che l'elenco 25H2
// non comprende.
func QualcommSeries(name string) string {
	n := cleanName(name)
	if m := qcModel.FindStringSubmatch(n); m != nil {
		return "x" + m[1] + strings.ToLower(m[2])
	}
	if m := qcWords.FindStringSubmatch(n); m != nil {
		gen := "1"
		if m[1] != "" {
			gen = "2"
		}
		return "x" + gen + strings.ToLower(m[2][:1])
	}
	return ""
}
