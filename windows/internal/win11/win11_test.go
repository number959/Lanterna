package win11

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Pagine di prova scritte a mano con la struttura delle pagine di Microsoft
// Learn (tabella con intestazione e righe): poche righe, prese come esempi
// dalla ricerca, non gli elenchi veri, che Polaris non incorpora.

func page(head []string, rows [][]string) string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><title>Prova</title><script>var t = "<table><tr><th>Manufacturer</th></tr></table>";</script></head><body>`)
	b.WriteString(`<!-- <table><tr><td>commento</td></tr></table> -->`)
	b.WriteString(`<table class="nav"><tr><td>Indice</td><td>Altro</td></tr></table>`)
	b.WriteString("<p>OEMs may use the following CPUs</p>\n<table>\n<thead>\n<tr>\n")
	for _, h := range head {
		fmt.Fprintf(&b, "<th>%s</th>\n", h)
	}
	b.WriteString("</tr>\n</thead>\n<tbody>\n")
	for _, r := range rows {
		b.WriteString("<tr>\n")
		for _, c := range r {
			fmt.Fprintf(&b, "<td>%s</td>\n", c)
		}
		b.WriteString("</tr>\n")
	}
	b.WriteString("</tbody>\n</table></body></html>")
	return b.String()
}

var amdPage = page([]string{"Manufacturer", "Brand", "Model"}, [][]string{
	{"AMD", "AMD", "3020e"},
	{"AMD", "Athlon&#8482;", "Gold 3150U"},
	{"AMD", "EPYC™", "7F52"},
	{"AMD", "EPYC™", "4124P\u200b"},
	{"AMD", "Ryzen Embedded R2000 Series", "R2314"},
	{"AMD", "Ryzen™ 3", "3250U"},
	{"AMD", "Ryzen™ 3", "5300G (OEM Only)"},
	{"AMD", "Ryzen™ 5", "2600"},
	{"AMD", "Ryzen™ 5", "3400G with Radeon™ RX Vega 11 Graphics"},
	{"AMD", "Ryzen™ 5", "3580U Microsoft Surface® Edition"},
	{"AMD", "Ryzen™ 7 PRO", "4750U"},
	{"AMD", "Ryzen™ Threadripper™ PRO", "3995WX"},
	{"AMD", "Ryzen™", "Z1 Extreme"},
})

var intelPage = page([]string{"Manufacturer", "Product Name", "Series"}, [][]string{
	{"Intel", "Intel Atom®", "Atom X7000 Series"},
	{"Intel", "Intel® Celeron®", "Celeron 3000 Series"},
	{"Intel", "Intel® Celeron®", "Celeron N4000 Series"},
	{"Intel", "Intel® Core™", "8th Generation Core i5 Processors"},
	{"Intel", "Intel® Core™", "11th Generation Core i5 Processors"},
	{"Intel", "Intel® Core™", "Core i7 processors (14th Generation)"},
	{"Intel", "Intel® Core™", "8th Generation Core m Processors"},
	{"Intel", "Intel® Core™", "Core Processor N300 Series"},
	{"Intel", "Intel® Core™", "Core Processors (Series 1)"},
	{"Intel", "Intel® Core™ Ultra", "Core Ultra Processors (Series 1)"},
	{"Intel", "Intel® Core™ Ultra", "Core Ultra Processors (Series 2)"},
	{"Intel", "Intel® Pentium®", "Pentium 6800 Series"},
	{"Intel", "Intel® Pentium®", "Pentium Gold 4000U Series"},
	{"Intel", "Intel® Pentium®", "Pentium Gold 6000 Series"},
	{"Intel", "Intel® Pentium®", "Pentium Silver J5000 Series"},
	{"Intel", "Intel® Processor", "Intel® 300 Processor for Desktop"},
	{"Intel", "Intel® Processor", "N100 Series"},
	{"Intel", "Intel® Processor", "N90 Series"},
	{"Intel", "Intel® Processor", "U300 series"},
	{"Intel", "Intel® Xeon®", "2nd Generation Xeon Scalable Processors"},
	{"Intel", "Intel® Xeon®", "Xeon W-1200 Series"},
	{"Intel", "Intel® Xeon®", "Xeon W-2400 Series"},
	{"Intel", "Intel® Xeon®", "Xeon W-11000M Series"},
	{"Intel", "Intel® Xeon®", "Xeon E-2300 Series"},
	{"Intel", "Intel® Xeon® 600", "Xeon 600 Processors for Workstation"},
})

var qualcommPage = page([]string{"Manufacturer", "Product Name", "Series"}, [][]string{
	{"Qualcomm®", "Snapdragon™ X", "X1"},
	{"Qualcomm®", "Snapdragon™ X Plus", "X1P"},
	{"Qualcomm®", "Snapdragon™ X Elite<sup>1</sup>", "X1E"},
	{"Qualcomm®", "Snapdragon™ X2 Elite", "X2E"},
})

func TestParseTable(t *testing.T) {
	head, rows := ParseTable(amdPage)
	if !reflect.DeepEqual(head, []string{"Manufacturer", "Brand", "Model"}) || len(rows) != 13 {
		t.Fatalf("tabella AMD: %v, %d righe", head, len(rows))
	}
	// Entità decodificate, spazio a larghezza zero tolto.
	if rows[1][1] != "Athlon™" || rows[3][2] != "4124P" {
		t.Errorf("celle: %q %q", rows[1][1], rows[3][2])
	}
	_, rows = ParseTable(qualcommPage)
	if len(rows) != 4 || rows[2][1] != "Snapdragon™ X Elite" {
		t.Errorf("rimando alla nota non tolto: %q", rows[2][1])
	}
	// Celle con tag, a capo e spazi; righe incomplete scartate.
	h, r := ParseTable(`<TABLE><TR><TH>Manufacturer</TH><TH>Series</TH></TR><TR><TD><a href="x">Intel</a></TD><TD>Core&nbsp;Ultra<br>Processors   (Series 2)</TD></TR><TR><TD>solo una</TD></TR></TABLE>`)
	if len(h) != 2 || len(r) != 1 || r[0][1] != "Core Ultra Processors (Series 2)" {
		t.Errorf("tag annidati: %v %v", h, r)
	}
	if h, r := ParseTable(`<html><body><p>Pagina senza tabella</p></body></html>`); h != nil || r != nil {
		t.Errorf("pagina senza tabella: %v %v", h, r)
	}
}

func TestAMDKeys(t *testing.T) {
	for name, want := range map[string]string{
		"AMD Ryzen 5 3500U with Radeon Vega Mobile Gfx":    "ryzen 5 3500u",
		"AMD Ryzen 3 3250U with Radeon Graphics":           "ryzen 3 3250u",
		"AMD Ryzen 7 PRO 4750U with Radeon Graphics":       "ryzen 7 pro 4750u",
		"AMD Ryzen 5 2600 Six-Core Processor":              "ryzen 5 2600",
		"AMD Ryzen 7 1700 Eight-Core Processor":            "ryzen 7 1700",
		"AMD Ryzen Threadripper PRO 3995WX 64-Cores":       "ryzen threadripper pro 3995wx",
		"AMD 3020e with Radeon Graphics":                   "3020e",
		"AMD EPYC 7F52 16-Core Processor":                  "epyc 7f52",
		"AMD Ryzen 7 7840HS w/ Radeon 780M Graphics":       "ryzen 7 7840hs",
		"AMD Ryzen(TM) 9 9950X 16-Core Processor":          "ryzen 9 9950x",
		"AMD Ryzen Embedded R2314 with Radeon Graphics":    "ryzen embedded r2314",
		"  AMD   Athlon  Gold 3150U with Radeon Graphics ": "athlon gold 3150u",
		"AMD Eng Sample": "",
	} {
		if got := AMDNameKey(name); got != want {
			t.Errorf("AMDNameKey(%q) = %q, atteso %q", name, got, want)
		}
	}
	for _, c := range [][3]string{
		{"Ryzen™ 7 PRO", "4750U", "ryzen 7 pro 4750u"},
		{"AMD", "3015e", "3015e"},
		{"Ryzen Embedded R2000 Series", "R2312", "ryzen embedded r2312"},
		{"Ryzen™ 3", "5300GE (OEM Only)", "ryzen 3 5300ge"},
		{"Ryzen™ 3", "3200G with Radeon™ Vega 8 Graphics", "ryzen 3 3200g"},
		{"Ryzen™ 7", "3780U Microsoft Surface® Edition", "ryzen 7 3780u"},
		{"Ryzen™ 7", "2700E Processor", "ryzen 7 2700e"},
	} {
		if got := AMDRowKey(c[0], c[1]); got != c[2] {
			t.Errorf("AMDRowKey(%q, %q) = %q, atteso %q", c[0], c[1], got, c[2])
		}
	}
}

func TestIntelSeries(t *testing.T) {
	for name, want := range map[string]string{
		"Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz":        "8th generation core i5 processors",
		"11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz":  "11th generation core i5 processors",
		"12th Gen Intel(R) Core(TM) i7-12700H":            "12th generation core i7 processors",
		"Intel(R) Core(TM) i7-1065G7 CPU @ 1.30GHz":       "10th generation core i7 processors",
		"Intel(R) Core(TM) i9-14900K":                     "core i9 processors (14th generation)",
		"Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz":        "7th generation core i7 processors",
		"Intel(R) Core(TM) i7 CPU         860  @ 2.80GHz": "",
		"Intel(R) Core(TM) i7-860 CPU @ 2.80GHz":          "1st generation core i7 processors",
		"Intel(R) Core(TM) i5-7640X CPU @ 4.00GHz":        "intel core 7000x series",
		"Intel(R) Core(TM) i9-10900X CPU @ 3.70GHz":       "intel core 10000x series",
		"Intel(R) Core(TM) i9-12900HX":                    "12th generation core i9 processors",
		"Intel(R) Core(TM) m3-8100Y CPU @ 1.10GHz":        "8th generation core m processors",
		"Intel(R) Core(TM) m3-7Y30 CPU @ 1.00GHz":         "7th generation core m processors",
		"Intel(R) Core(TM) i3-N305":                       "core processor n300 series",
		"Intel(R) Core(TM) Ultra 7 155H":                  "core ultra processors (series 1)",
		"Intel(R) Core(TM) Ultra 9 285K":                  "core ultra processors (series 2)",
		"Intel(R) Core(TM) 7 150U":                        "core processors (series 1)",
		"Intel(R) N100":                                   "n100 series",
		"Intel(R) N95":                                    "n90 series",
		"Intel(R) N150":                                   "n150 series", // Twin Lake: non è la serie N100
		"Intel(R) Processor N250":                         "n250 series",
		"Intel(R) Processor N200":                         "n200 series",
		"Intel(R) Processor U300":                         "u300 series",
		"Intel(R) Processor 300":                          "intel 300 processor for desktop",
		"Intel Atom(R) x7425E":                            "atom x7000 series",
		"Intel(R) Celeron(R) CPU 3865U @ 1.80GHz":         "celeron 3000 series",
		"Intel(R) Celeron(R) N4020 CPU @ 1.10GHz":         "celeron n4000 series",
		"Intel(R) Celeron(R) CPU N3350 @ 1.10GHz":         "celeron n3000 series",
		"Intel(R) Celeron(R) CPU G4900 @ 3.10GHz":         "celeron g4000 series",
		"Intel(R) Pentium(R) CPU 4415U @ 2.30GHz":         "pentium gold 4000u series",
		"Intel(R) Pentium(R) Gold 6405U CPU @ 2.40GHz":    "pentium gold 6000u series",
		"Intel(R) Pentium(R) Silver N5030 CPU @ 1.10GHz":  "pentium silver n5000 series",
		"Intel(R) Pentium(R) CPU G4560 @ 3.50GHz":         "pentium gold g4000 series",
		"Intel(R) Pentium(R) CPU J5005 @ 1.50GHz":         "pentium silver j5000 series",
		"Intel(R) Pentium(R) 6805 @ 1.10GHz":              "pentium 6800 series",
		"Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz":       "2nd generation xeon scalable processors",
		"Intel(R) Xeon(R) Gold 6130 CPU @ 2.10GHz":        "xeon scalable processors",
		"Intel(R) Xeon(R) W-1290P CPU @ 3.70GHz":          "xeon w-1200 series",
		"Intel(R) Xeon(R) W-11955M CPU @ 2.60GHz":         "xeon w-11000m series",
		"Intel(R) Xeon(R) w5-2455X":                       "xeon w-2400 series",
		"Intel(R) Xeon(R) E-2336 CPU @ 2.90GHz":           "xeon e-2300 series",
		"Intel(R) Xeon(R) CPU E3-1230 v5 @ 3.40GHz":       "xeon e3-1200 series",
		"Intel(R) Xeon(R) 698X":                           "xeon 600 processors for workstation",
		"Intel(R) Core(TM)2 Duo CPU     E8400  @ 3.00GHz": "",
		"Genuine Intel(R) CPU 0000 @ 2.40GHz":             "",
	} {
		got := IntelSeries(name)
		first := ""
		if len(got) > 0 {
			first = got[0]
		}
		if first != want {
			t.Errorf("IntelSeries(%q) = %v, attesa %q", name, got, want)
		}
	}
	// Pentium Gold con la U: prima la serie con la lettera, poi quella senza.
	if got := IntelSeries("Intel(R) Pentium(R) Gold 6405U"); !reflect.DeepEqual(got, []string{"pentium gold 6000u series", "pentium gold 6000 series"}) {
		t.Errorf("Pentium Gold 6405U: %v", got)
	}
}

func TestQualcommSeries(t *testing.T) {
	for name, want := range map[string]string{
		"Snapdragon(R) X Elite - X1E78100 - Qualcomm(R) Oryon(TM) CPU": "x1e",
		"Snapdragon(R) X 10-core X1P64100 @ 3.40 GHz":                  "x1p",
		"Snapdragon X1-26-100":                                         "x1",
		"Snapdragon(R) X2 Elite":                                       "x2e",
		"Snapdragon X Plus":                                            "x1p",
		"Snapdragon (TM) 8cx Gen 3 @ 3.0 GHz":                          "",
		"Microsoft SQ3 @ 3.0 GHz":                                      "",
	} {
		if got := QualcommSeries(name); got != want {
			t.Errorf("QualcommSeries(%q) = %q, attesa %q", name, got, want)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		list, cpu, result, match string
	}{
		{"amd", "AMD Ryzen 7 PRO 4750U with Radeon Graphics", "listed", "Ryzen 7 PRO 4750U"},
		{"amd", "AMD Ryzen 3 3250U with Radeon Graphics", "listed", "Ryzen 3 3250U"},
		{"amd", "AMD Ryzen 5 2600 Six-Core Processor", "listed", "Ryzen 5 2600"},
		{"amd", "AMD Ryzen 3 5300G with Radeon Graphics", "listed", "Ryzen 3 5300G (OEM Only)"},
		{"amd", "AMD Ryzen 5 3400G with Radeon Vega Graphics", "listed", "Ryzen 5 3400G with Radeon RX Vega 11 Graphics"},
		{"amd", "AMD 3020e with Radeon Graphics", "listed", "3020e"},
		{"amd", "AMD EPYC 7F52 16-Core Processor", "listed", "EPYC 7F52"},
		{"amd", "AMD EPYC 4124P 4-Core Processor", "listed", "EPYC 4124P"},
		{"amd", "AMD Ryzen Embedded R2314 with Radeon Graphics", "listed", "Ryzen Embedded R2000 Series R2314"},
		{"amd", "AMD Ryzen Threadripper PRO 3995WX 64-Cores", "listed", "Ryzen Threadripper PRO 3995WX"},
		{"amd", "AMD Ryzen Z1 Extreme", "listed", "Ryzen Z1 Extreme"},
		{"amd", "AMD Ryzen 7 1700 Eight-Core Processor", "notListed", ""},
		{"amd", "AMD Ryzen 9 9950X 16-Core Processor", "notListed", ""},
		{"amd", "QEMU Virtual CPU version 2.5+", "unknown", ""},
		{"intel", "Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz", "listed", "8th Generation Core i5 Processors"},
		{"intel", "11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz", "listed", "11th Generation Core i5 Processors"},
		{"intel", "Intel(R) Core(TM) i7-14700K", "listed", "Core i7 processors (14th Generation)"},
		{"intel", "Intel(R) Core(TM) Ultra 7 258V", "listed", "Core Ultra Processors (Series 2)"},
		{"intel", "Intel(R) Celeron(R) N4120 CPU @ 1.10GHz", "listed", "Celeron N4000 Series"},
		{"intel", "Intel(R) Pentium(R) Gold 6405U CPU @ 2.40GHz", "listed", "Pentium Gold 6000 Series"},
		{"intel", "Intel(R) N97", "listed", "N90 Series"},
		{"intel", "Intel(R) N100", "listed", "N100 Series"},
		// Twin Lake: la riga «N100 Series» non lo comprende.
		{"intel", "Intel(R) N150", "notListed", ""},
		{"intel", "Intel(R) Processor 300", "listed", "Intel 300 Processor for Desktop"},
		{"intel", "Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz", "listed", "2nd Generation Xeon Scalable Processors"},
		// Serie dell'elenco troppo larghe: decide il modello, da verificare.
		{"intel", "Intel(R) Celeron(R) CPU 3865U @ 1.80GHz", "unknown", "Celeron 3000 Series"},
		{"intel", "Intel(R) Pentium(R) CPU 4415U @ 2.30GHz", "unknown", "Pentium Gold 4000U Series"},
		{"intel", "Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz", "notListed", ""},
		{"intel", "Intel(R) Pentium(R) Silver N5030 CPU @ 1.10GHz", "notListed", ""},
		{"intel", "Intel(R) Celeron(R) CPU N3350 @ 1.10GHz", "notListed", ""},
		{"intel", "Intel(R) Xeon(R) CPU E3-1230 v5 @ 3.40GHz", "notListed", ""},
		{"intel", "Intel(R) Core(TM)2 Duo CPU E8400 @ 3.00GHz", "unknown", ""},
		{"intel", "Common KVM processor", "unknown", ""},
		{"qualcomm", "Snapdragon(R) X Elite - X1E78100 - Qualcomm(R) Oryon(TM) CPU", "listed", "X1E"},
		{"qualcomm", "Snapdragon (TM) 8cx Gen 3 @ 3.0 GHz", "unknown", ""},
	}
	pages := map[string]string{"amd": amdPage, "intel": intelPage, "qualcomm": qualcommPage}
	for _, c := range cases {
		head, rows := ParseTable(pages[c.list])
		result, match := Compare(Lists[c.list], head, rows, c.cpu)
		if result != c.result || match != c.match {
			t.Errorf("%s %q: %s %q, attesi %s %q", c.list, c.cpu, result, match, c.result, c.match)
		}
	}
}

func TestVendorOf(t *testing.T) {
	for _, c := range [][3]string{
		{"GenuineIntel", "Intel(R) Core(TM) i5-8250U", "intel"},
		{"AuthenticAMD", "AMD Ryzen 5 2600", "amd"},
		{"", "Snapdragon(R) X Elite - X1E78100", "qualcomm"},
		{"Qualcomm Technologies Inc", "", "qualcomm"},
		{"", "AMD Ryzen 7 5800H", "amd"},
		{"", "Intel(R) N100", "intel"},
		{"", "Apple M2", ""},
	} {
		if got := VendorOf(c[0], c[1]); got != c[2] {
			t.Errorf("VendorOf(%q, %q) = %q, atteso %q", c[0], c[1], got, c[2])
		}
	}
}

func TestCheck(t *testing.T) {
	var body, ctype string
	mux := http.NewServeMux()
	mux.HandleFunc("/elenco", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "STARNET-Polaris/prova" {
			t.Errorf("User-Agent: %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write([]byte(body))
	})
	mux.HandleFunc("/altrove", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/elenco", http.StatusFound)
	})
	mux.HandleFunc("/grande", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(strings.Repeat("x", maxPage+10)))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	now := func() time.Time { return time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC) }
	opt := func(path, cpu, vendor string) Options {
		return Options{Transport: srv.Client().Transport, UserAgent: "STARNET-Polaris/prova", CPU: cpu, Vendor: vendor, Now: now, Hosts: []string{"127.0.0.1"}, URL: srv.URL + path}
	}
	ctx := context.Background()

	body, ctype = intelPage, "text/html; charset=utf-8"
	r := Check(ctx, opt("/elenco", "Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz", "GenuineIntel"))
	if r.Result != "listed" || r.Match != "8th Generation Core i5 Processors" || r.Version != "25H2" || r.Kind != "series" || r.Rows != 25 || r.Error != "" || r.At != "2026-11-17T10:00:00Z" || r.CPU != "Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz" {
		t.Errorf("Intel: %+v", r)
	}
	body = amdPage
	r = Check(ctx, opt("/elenco", "AMD Ryzen 7 PRO 4750U with Radeon Graphics", "AuthenticAMD"))
	if r.Result != "listed" || r.Version != "24H2" || r.Kind != "model" || r.Rows != 13 {
		t.Errorf("AMD: %+v", r)
	}
	// La pagina AMD letta come elenco Intel: intestazione diversa, formato cambiato.
	r = Check(ctx, opt("/elenco", "Intel(R) N100", "GenuineIntel"))
	if r.Result != "unknown" || !strings.Contains(r.Error, "formato") {
		t.Errorf("formato cambiato: %+v", r)
	}
	ctype = "application/json"
	if r = Check(ctx, opt("/elenco", "AMD Ryzen 5 2600", "AuthenticAMD")); r.Result != "unknown" || !strings.Contains(r.Error, "inatteso") {
		t.Errorf("contenuto non HTML: %+v", r)
	}
	if r = Check(ctx, opt("/altrove", "AMD Ryzen 5 2600", "AuthenticAMD")); r.Result != "unknown" || !strings.Contains(r.Error, "learn.microsoft.com") {
		t.Errorf("rimando verso un altro sito: %+v", r)
	}
	if r = Check(ctx, opt("/grande", "AMD Ryzen 5 2600", "AuthenticAMD")); !strings.Contains(r.Error, "più grande") {
		t.Errorf("pagina troppo grande: %+v", r)
	}
	if r = Check(ctx, opt("/manca", "AMD Ryzen 5 2600", "AuthenticAMD")); !strings.Contains(r.Error, "404") {
		t.Errorf("pagina inesistente: %+v", r)
	}
	// Solo https.
	o := opt("/elenco", "AMD Ryzen 5 2600", "AuthenticAMD")
	o.URL = strings.Replace(srv.URL, "https://", "http://", 1) + "/elenco"
	if r = Check(ctx, o); r.Error == "" || r.Rows != 0 {
		t.Errorf("indirizzo http accettato: %+v", r)
	}
	// Host predefinito: un indirizzo che non è learn.microsoft.com si rifiuta prima di collegarsi.
	o = opt("/elenco", "AMD Ryzen 5 2600", "AuthenticAMD")
	o.Hosts = nil
	if r = Check(ctx, o); !strings.Contains(r.Error, "learn.microsoft.com") {
		t.Errorf("host non ammesso: %+v", r)
	}
	// Produttore sconosciuto: nessun collegamento.
	if r = Check(ctx, Options{CPU: "Apple M2", Now: now}); r.Result != "unknown" || r.Source != "" || !strings.Contains(r.Error, "produttore") {
		t.Errorf("produttore sconosciuto: %+v", r)
	}
	// Gli indirizzi veri sono https su learn.microsoft.com.
	for v, l := range Lists {
		if !strings.HasPrefix(l.URL, "https://learn.microsoft.com/") || l.Vendor != v || (l.Kind != "model" && l.Kind != "series") {
			t.Errorf("elenco %s: %+v", v, l)
		}
	}
}

// Gli errori di rete diventano frasi fisse in italiano: niente testo di Go,
// URL o indirizzi IP del server o del proxy nel rapporto.
func TestNetText(t *testing.T) {
	ip := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(13, 107, 246, 45), Port: 443}, Err: errors.New("connectex: timeout")}
	for _, c := range []struct {
		err  error
		want string
	}{
		{&url.Error{Op: "Get", URL: "https://learn.microsoft.com/x", Err: &net.OpError{Op: "proxyconnect", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 3128}, Err: errors.New("connect: connection refused")}}, "proxy di sistema non risponde"},
		{&url.Error{Op: "Get", URL: "https://learn.microsoft.com/x", Err: &net.OpError{Op: "proxyconnect", Net: "tcp", Err: errors.New("Proxy Authentication Required")}}, "autenticazione"},
		// Forma vera del 407 al CONNECT in net/http: solo il testo dello stato.
		{&url.Error{Op: "Get", URL: "https://learn.microsoft.com/x", Err: errors.New("Proxy Authentication Required")}, "autenticazione"},
		{&url.Error{Op: "Get", URL: "https://learn.microsoft.com/x", Err: &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "learn.microsoft.com"}}}, "nome del sito non risolto"},
		{&url.Error{Op: "Get", URL: "https://learn.microsoft.com/x", Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}}, "connessione cifrata non verificabile"},
		{&url.Error{Op: "Get", URL: "https://learn.microsoft.com/x", Err: x509.HostnameError{Host: "learn.microsoft.com"}}, "connessione cifrata non verificabile"},
		{&url.Error{Op: "Get", URL: "https://learn.microsoft.com/x", Err: ip}, "connessione non riuscita"},
	} {
		got := netText(c.err)
		if !strings.Contains(got, c.want) {
			t.Errorf("netText(%v) = %q, atteso %q", c.err, got, c.want)
		}
		if regexp.MustCompile(`\d+\.\d+\.\d+\.\d+|dial|Get "|https?:`).MatchString(got) {
			t.Errorf("testo tecnico o indirizzo nell'errore: %q", got)
		}
	}
}

func TestCheckNetworkErrors(t *testing.T) {
	ipv4 := regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)
	clean := func(what, e string) {
		t.Helper()
		if e == "" || ipv4.MatchString(e) || strings.Contains(e, "dial") || strings.Contains(e, `Get "`) || strings.Contains(e, "127.0.0.1") {
			t.Errorf("%s: errore %q", what, e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// Connessione rifiutata: porta chiusa sull'indirizzo locale.
	r := Check(ctx, Options{CPU: "Intel(R) Core(TM) i5-8250U", Vendor: "GenuineIntel", Hosts: []string{"127.0.0.1"}, URL: "https://127.0.0.1:1/elenco"})
	clean("connessione rifiutata", r.Error)
	if r.Result != "unknown" || r.Rows != 0 || !strings.HasPrefix(r.Error, "learn.microsoft.com non raggiungibile") {
		t.Errorf("connessione rifiutata: %+v", r)
	}
	// Proxy di sistema che non risponde.
	proxy, _ := url.Parse("http://127.0.0.1:1")
	r = Check(ctx, Options{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, CPU: "Intel(R) Core(TM) i5-8250U", Vendor: "GenuineIntel"})
	clean("proxy", r.Error)
	if !strings.Contains(r.Error, "proxy") {
		t.Errorf("proxy che non risponde: %+v", r)
	}
	// Proxy aziendale che chiede le credenziali (407 al CONNECT): net/http
	// restituisce solo il testo dello stato, senza *net.OpError.
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodConnect {
			t.Errorf("richiesta al proxy: %s", req.Method)
		}
		w.Header().Set("Proxy-Authenticate", `Basic realm="azienda"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer auth.Close()
	authURL, _ := url.Parse(auth.URL)
	r = Check(ctx, Options{Transport: &http.Transport{Proxy: http.ProxyURL(authURL)}, CPU: "Intel(R) Core(TM) i5-8250U", Vendor: "GenuineIntel"})
	clean("proxy con autenticazione", r.Error)
	if !strings.Contains(r.Error, "chiede un'autenticazione") {
		t.Errorf("proxy con autenticazione: %+v", r)
	}
}
