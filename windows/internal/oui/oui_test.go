package oui

import (
	"bytes"
	"compress/gzip"
	"math/rand/v2"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// gz comprime un elenco di prova.
func gz(t testing.TB, text string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// L'elenco incorporato si legge, è ordinato, senza prefissi ripetuti e con
// nomi già abbreviati: rigenerarlo con scripts/oui.sh dopo ogni modifica a
// Normalize.
func TestEmbedded(t *testing.T) {
	ix, err := parse(bytes.NewReader(embedded))
	if err != nil {
		t.Fatal(err)
	}
	// Elenco del 10 novembre 2026: MA-S 7235, MA-M 6601, MA-L 39906 blocchi.
	total := 0
	for i, min := range [3]int{5000, 5000, 35000} {
		tab := ix.tables[i]
		if len(tab) < min {
			t.Errorf("prefissi di %d cifre: %d, attesi almeno %d", digits[i], len(tab), min)
		}
		for j, e := range tab {
			if e>>nameBits >= 1<<(4*digits[i]) {
				t.Errorf("prefisso %x più lungo di %d cifre", e>>nameBits, digits[i])
			}
			if j > 0 && e>>nameBits <= tab[j-1]>>nameBits {
				t.Errorf("prefisso %x fuori ordine o ripetuto", e>>nameBits)
			}
		}
		total += len(tab)
	}
	if Count() != total {
		t.Errorf("Count() = %d, voci lette %d", Count(), total)
	}
	if !regexp.MustCompile(`^20\d\d-[01]\d-[0-3]\d$`).MatchString(Date()) {
		t.Errorf("Date() = %q", Date())
	}
	for i := range ix.ends {
		n := ix.name(uint64(i))
		if n == "" || Normalize(n) != n || strings.ContainsAny(n, "\t\n") ||
			strings.EqualFold(n, "Private") || strings.EqualFold(n, "IEEE Registration Authority") {
			t.Errorf("nome non valido: %q (Normalize: %q)", n, Normalize(n))
		}
	}
	// I blocchi suddivisi in MA-M e MA-S appartengono alla IEEE
	// Registration Authority, che non è un produttore: non sono tra gli MA-L,
	// così una parte non assegnata resta senza nome.
	for i, tab := range ix.tables[:2] {
		for _, e := range tab {
			p := e >> nameBits >> (4 * (digits[i] - 6))
			if _, ok := ix.find(2, p); ok {
				t.Errorf("il blocco MA-L %06X contiene blocchi più piccoli", p)
			}
		}
	}
	mem := len(ix.names) + 4*len(ix.ends) + 8*total
	t.Logf("%d blocchi, %d nomi distinti, circa %d KB in memoria, scaricato il %s", total, len(ix.ends), mem/1024, Date())
	if mem > 2<<20 {
		t.Errorf("elenco in memoria troppo grande: %d byte", mem)
	}
}

func TestLookupKnown(t *testing.T) {
	// Verificati sull'elenco del 10 novembre 2026; tra virgolette il nome
	// come lo scrive la IEEE.
	for mac, want := range map[string]string{
		"00:00:0c:07:ac:01": "Cisco",             // MA-L 00000C "Cisco Systems, Inc" (indirizzo virtuale HSRP)
		"00:1b:a9:12:34:56": "Brother",           // MA-L 001BA9 "Brother industries, LTD."
		"30:05:5c:aa:bb:cc": "Brother",           // MA-L 30055C "Brother industries, LTD."
		"3c:2a:f4:01:02:03": "Brother",           // MA-L 3C2AF4 "Brother Industries, LTD."
		"b8:27:eb:12:34:56": "Raspberry Pi",      // MA-L B827EB "Raspberry Pi Foundation"
		"dc:a6:32:12:34:56": "Raspberry Pi",      // MA-L DCA632 "Raspberry Pi Trading Ltd"
		"2c:cf:67:12:34:56": "Raspberry Pi",      // MA-L 2CCF67 "Raspberry Pi (Trading) Ltd"
		"00:50:56:c0:00:08": "VMware",            // MA-L 005056 "VMware, Inc."
		"00:15:5d:01:02:03": "Microsoft",         // MA-L 00155D "Microsoft Corporation" (Hyper-V)
		"3c:a6:2f:12:34:56": "AVM",               // MA-L 3CA62F "AVM Audiovisuelles Marketing und Computersysteme GmbH"
		"00:11:32:12:34:56": "Synology",          // MA-L 001132 "Synology Incorporated"
		"24:0a:c4:12:34:56": "Espressif",         // MA-L 240AC4 "Espressif Inc."
		"d8:5d:4c:12:34:56": "TP-Link",           // MA-L D85D4C "TP-LINK TECHNOLOGIES CO.,LTD."
		"6c:5a:b0:12:34:56": "TP-Link",           // MA-L 6C5AB0 "TP-Link Systems Inc"
		"00:09:5b:12:34:56": "Netgear",           // MA-L 00095B "NETGEAR"
		"00:17:88:12:34:56": "Philips Lighting",  // MA-L 001788 "Philips Lighting BV"
		"d0:14:11:a0:00:01": "ABB EVI",           // MA-M D01411A "ABB EVI SPA"
		"d0:14:11:1f:ff:ff": "P.B. Elettronica",  // MA-M D014111 "P.B. Elettronica srl"
		"70:b3:d5:29:81:23": "Reflexion Medical", // MA-S 70B3D5298 "Reflexion Medical"
		"70:b3:d5:29:cf:ff": "Teko Telecom",      // MA-S 70B3D529C "Teko Telecom Srl"
		// Non assegnati al 10 novembre 2026: MA-S 70B3D5000 e MA-M D01411F
		// (nei blocchi della IEEE Registration Authority), MA-L FCFFFF.
		"70:b3:d5:00:01:23": "",
		"d0:14:11:f0:00:01": "",
		"fc:ff:ff:12:34:56": "",
	} {
		if got := Lookup(mac); got != want {
			t.Errorf("Lookup(%s) = %q, atteso %q", mac, got, want)
		}
	}
}

func TestLookupNotations(t *testing.T) {
	for _, mac := range []string{
		"00:00:0c:12:34:56", "00:00:0C:12:34:56", "00-00-0c-12-34-56", "00-00-0C-12-34-56",
		"0000.0c12.3456", "0000.0C12.3456", "00000c123456", "00000C123456",
	} {
		if got := Lookup(mac); got != "Cisco" {
			t.Errorf("Lookup(%s) = %q", mac, got)
		}
	}
	for _, mac := range []string{"70:B3:D5:29:81:23", "70-b3-d5-29-81-23", "70b3.d529.8123"} {
		if got := Lookup(mac); got != "Reflexion Medical" {
			t.Errorf("Lookup(%s) = %q", mac, got)
		}
	}
}

func TestLookupRejects(t *testing.T) {
	for _, mac := range []string{
		// Di gruppo: multicast e broadcast, anche con un prefisso noto
		// (01:00:0c è il multicast di Cisco per CDP).
		"01:00:5e:00:00:fb", "33:33:00:00:00:01", "01:80:c2:00:00:0e", "01:00:0c:cc:cc:cc", "ff:ff:ff:ff:ff:ff",
		// Amministrati localmente: casuali o virtuali, anche con un prefisso noto.
		"02:00:0c:12:34:56", "da:a1:19:00:00:77", "0a:00:27:00:00:00", "06:15:5d:01:02:03",
		// Nulli o non inizializzati (00:00:00 è un prefisso di Xerox).
		"00:00:00:00:00:00", "00:00:00:12:34:56",
		// Non validi o non a 48 bit.
		"", "cisco", "00:00:0c", "00:00:0c:12:34", "00:00:0c:12:34:5", "00:00:0c:12:34:567",
		"00:00:0c:12:34:56:78", "00:00:0c:12:34:56:78:9a", "0000.0c12.3456.789a", "00:00:0c:12:34:56:",
		"00:00:0g:12:34:56", "00-00:0c:12:34:56", "00.00.0c.12.34.56", "0000:0c12:3456",
		"00000c12345", "00000c1234567", "00000c123456789a", "0:0:c:12:34:56",
		" 00:00:0c:12:34:56", "00:00:0c:12:34:56 ", "00:00:0c:12:34:56\n",
	} {
		if got := Lookup(mac); got != "" {
			t.Errorf("Lookup(%q) = %q, atteso vuoto", mac, got)
		}
	}
}

// I MAC casuali di telefoni e PC sono amministrati localmente: nessun nome.
func TestLookupRandomMAC(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		var b [6]byte
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		b[0] = b[0]&^0x01 | 0x02 // individuale, amministrato localmente
		if got := Lookup(net.HardwareAddr(b[:]).String()); got != "" {
			t.Fatalf("Lookup(%s) = %q", net.HardwareAddr(b[:]), got)
		}
	}
}

// Vince il blocco più lungo: MA-S (36 bit), poi MA-M (28), poi MA-L (24).
func TestLongestPrefix(t *testing.T) {
	ix, err := parse(bytes.NewReader(gz(t, "# commento\n# scaricato: 2026-01-02 (UTC)\n"+
		"00112233A\tPiccolo\n0011225\tMedio\n001122\tGrande\n0011224\tMedio\n")))
	if err != nil {
		t.Fatal(err)
	}
	for mac, want := range map[string]string{
		"00:11:22:33:a0:00": "Piccolo",
		"00:11:22:33:af:ff": "Piccolo",
		"00:11:22:33:b0:00": "Grande", // MA-S assente, MA-M 0011223 assente
		"00:11:22:40:00:00": "Medio",
		"00:11:22:5f:ff:ff": "Medio",
		"00:11:22:60:00:00": "Grande",
		"00:11:23:00:00:00": "",
		"00:11:21:ff:ff:ff": "",
	} {
		if got := ix.lookup(mac); got != want {
			t.Errorf("lookup(%s) = %q, atteso %q", mac, got, want)
		}
	}
	if ix.date != "2026-01-02" || len(ix.ends) != 3 || ix.names != "PiccoloMedioGrande" {
		t.Errorf("data %q, nomi %q %v", ix.date, ix.names, ix.ends)
	}
	if got := (&index{}).lookup("00:00:0c:12:34:56"); got != "" {
		t.Errorf("elenco vuoto: %q", got)
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{
		"001122 Grande\n",            // manca il TAB
		"00112\tCorto\n",             // 5 cifre
		"00112G\tNon esadecimale\n",  // cifra non valida
		"0011223344\tTroppo lungo\n", // 10 cifre
		"001122\t\n",                 // nome vuoto
		"\tSenza prefisso\n",
	} {
		if _, err := parse(bytes.NewReader(gz(t, bad))); err == nil {
			t.Errorf("accettato: %q", bad)
		}
	}
	if _, err := parse(strings.NewReader("001122\tNon compresso\n")); err == nil {
		t.Error("accettato un file non compresso")
	}
	b := gz(t, "001122\tGrande\n")
	if _, err := parse(bytes.NewReader(b[:len(b)-4])); err == nil {
		t.Error("accettato un file troncato")
	}
	b[len(b)-8] ^= 0xff // somma di controllo CRC-32 sbagliata
	if _, err := parse(bytes.NewReader(b)); err == nil {
		t.Error("accettato un file danneggiato")
	}
}

func TestLookupConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				if got := Lookup("00:00:0c:12:34:56"); got != "Cisco" {
					t.Errorf("Lookup = %q", got)
					return
				}
			}
		})
	}
	wg.Wait()
}

func BenchmarkLookup(b *testing.B) {
	Lookup("00:00:0c:12:34:56") // decompressione al primo uso, fuori dalla misura
	b.ReportAllocs()
	for b.Loop() {
		Lookup("d8:5d:4c:12:34:56")
	}
}

func BenchmarkParse(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parse(bytes.NewReader(embedded)); err != nil {
			b.Fatal(err)
		}
	}
}
