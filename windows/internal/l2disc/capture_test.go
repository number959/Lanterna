package l2disc

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestClampDuration(t *testing.T) {
	cases := map[time.Duration]time.Duration{
		0:                        DefaultDuration,
		-time.Second:             DefaultDuration,
		500 * time.Millisecond:   time.Second,
		61700 * time.Millisecond: 61 * time.Second,
		10 * time.Minute:         maxDuration,
	}
	for in, want := range cases {
		if got := clampDuration(in); got != want {
			t.Errorf("clampDuration(%v) = %v, atteso %v", in, got, want)
		}
	}
}

func TestCaptureScript(t *testing.T) {
	s := captureScript
	for _, a := range listenAddresses {
		if !strings.Contains(s, "'"+a+"'") {
			t.Errorf("indirizzo %s assente dal filtro", a)
		}
	}
	for _, want := range []string{
		"$env:POLARIS_L2_SESSION", "$env:POLARIS_L2_ETL", "$env:POLARIS_L2_SECONDS",
		"New-NetEventSession -Name $name -CaptureMode SaveToFile -LocalFilePath $etl",
		"-CaptureType Physical", "-TruncationLength 0", "-PromiscuousMode $true",
		"Start-NetEventSession", "Stop-NetEventSession", "Remove-NetEventSession -Name $name",
		"} finally {", "Remove-Item -LiteralPath $etl", "'L2CLEAN'",
		"-like 'Polaris-L2-*'", "'L2BUSY'", "'L2NOWIRED'",
		"Get-WinEvent -Path $etl -Oldest -FilterXPath '*[System[EventID=1001]]'",
		"GetAttribute('Name')", "'Fragment'", "'MiniportIfIndex'",
		"Event/EventData/Data[@Name='Fragment']", "0x100000000",
		"Start-Sleep -Milliseconds 250",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("lo script non contiene %q", want)
		}
	}
	if strings.Contains(s, "@ADDRS@") || strings.Contains(s, "@PREFIX@") {
		t.Fatal("segnaposto non sostituiti")
	}
	// Il finally deve venire dopo la creazione della sessione e chiudere lo script.
	if i, j := strings.Index(s, "New-NetEventSession -Name"), strings.Index(s, "} finally {"); i < 0 || j < i {
		t.Fatal("la sessione va creata dentro il try con il finally")
	}
	for _, sc := range []string{captureScript, cleanupScript} {
		if strings.Count(sc, "{") != strings.Count(sc, "}") || strings.Count(sc, "(") != strings.Count(sc, ")") || strings.Count(sc, "[") != strings.Count(sc, "]") {
			t.Errorf("parentesi non bilanciate:\n%s", sc)
		}
		// Nessuna stringa su più righe: apici e virgolette pari su ogni riga.
		for i, line := range strings.Split(sc, "\n") {
			if strings.Count(line, "'")%2 != 0 || strings.Count(line, `"`)%2 != 0 {
				t.Errorf("riga %d con apici dispari: %s", i+1, line)
			}
		}
		// Nessun percorso scritto nello script: arrivano dalle variabili d'ambiente.
		if strings.Contains(strings.ToLower(sc), `c:\`) || strings.Contains(strings.ToLower(sc), `\users\`) {
			t.Error("percorso nello script")
		}
	}
	if !strings.Contains(cleanupScript, "Stop-NetEventSession -Name $name") || !strings.Contains(cleanupScript, "Remove-NetEventSession -Name $name") {
		t.Fatal(cleanupScript)
	}
}

func hexUpper(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }

// dashed scrive i byte come "01-80-C2-...".
func dashed(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = hexUpper([]byte{x})
	}
	return strings.Join(parts, "-")
}

func TestParseCaptureOutput(t *testing.T) {
	own := cat(dstLLDP, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}, switchLLDP()[12:]) // trasmessa dal PC
	out := strings.Join([]string{
		"L2A 12 AA-BB-CC-DD-EE-01 Ethernet 2",
		"L2A 15  Dock USB",
		"L2START",
		"L2EVENTS 6",
		"L2F R 12 " + hexUpper(switchLLDP()),
		"L2F S 12 " + hexUpper(switchCDP()),
		"L2F R 12 " + hexUpper(own),
		"L2F R 15 0x" + hexUpper(dtpFrame(0x03, 0xa5)),
		"L2F R 99 " + dashed(sampleFrames()[3]), // come BitConverter.ToString, scheda sconosciuta
		"L2F R 12 zz-non-esadecimale",
		"L2F R 12",
		"testo qualunque di PowerShell",
		"L2END",
		"L2CLEAN",
	}, "\r\n")
	c := parseCapture(out)
	if !c.started || !c.ended || !c.clean || c.events != 6 || c.own != 2 || c.bad != 2 || len(c.frames) != 3 {
		t.Fatalf("%+v", c)
	}
	if !reflect.DeepEqual(c.adapters, []string{"Ethernet 2", "Dock USB"}) {
		t.Fatalf("%q", c.adapters)
	}
	d := c.discovery(61)
	if d.Read != ReadOK || d.Seconds != 61 || d.Frames != 3 || d.Error != "" {
		t.Fatalf("%+v", d)
	}
	if d.Lldp[0].Adapter != "Ethernet 2" || d.Dtp[0].Adapter != "Dock USB" || d.Stp[0].Adapter != "" {
		t.Fatalf("schede: %q %q %q", d.Lldp[0].Adapter, d.Dtp[0].Adapter, d.Stp[0].Adapter)
	}
	if len(d.Cdp) != 0 {
		t.Fatal("le trame trasmesse dal PC vanno scartate")
	}
}

func TestCaptureOutcomes(t *testing.T) {
	cases := []struct {
		out     string
		read    string
		errPart string
		seconds int
	}{
		{"L2NOMODULE", ReadUnsupported, "NetEventPacketCapture", 0},
		{"L2NOWIRED", ReadNoWired, "cablata", 0},
		{"\uFEFFL2NOWIRED\r\n", ReadNoWired, "cablata", 0}, // BOM di Windows PowerShell
		{"L2A 3 AA-BB-CC-DD-EE-FF Ethernet\nL2BUSY", ReadError, "altra sessione", 0},
		{"L2A 3 AA-BB-CC-DD-EE-FF Ethernet\nL2FAIL session AccessDenied\nL2CLEAN", ReadAdmin, "(codice AccessDenied)", 0},
		{"L2A 3 AA-BB-CC-DD-EE-FF Ethernet\nL2FAIL provider 0x80041008\nL2CLEAN", ReadError, "filtro della cattura (codice 0x80041008)", 0},
		{"L2START\nL2FAIL read 0x80070002 C:\\Users\\mario\nL2CLEAN", ReadError, "non si legge (codice 0x80070002)", 61},
		{"L2FAIL nuova-fase !!", ReadError, "Cattura non riuscita.", 0},
		{"L2START", ReadError, "non conclusa", 61},
		{"", ReadError, "non conclusa", 0},
		{"L2START\nL2EVENTS 0\nL2END\nL2CLEAN", ReadNone, "", 61},
		{"L2START\nL2EVENTS 2\nL2F R 3 \nL2F R 3 0102\nL2END\nL2CLEAN", ReadError, "non leggibile", 61},
	}
	for _, c := range cases {
		co := parseCapture(c.out)
		d := co.discovery(61)
		if d.Read != c.read || !strings.Contains(d.Error, c.errPart) || d.Seconds != c.seconds {
			t.Errorf("%q: %+v", c.out, d)
		}
		if strings.Contains(d.Error, "mario") || strings.Contains(d.Error, "Users") {
			t.Errorf("percorso nel messaggio: %q", d.Error)
		}
		wantUnfinished := c.read == ReadError && strings.Contains(c.errPart, "non conclusa")
		if co.unfinished() != wantUnfinished {
			t.Errorf("%q: unfinished = %v", c.out, co.unfinished())
		}
	}
	if d := parseCapture("L2FAIL session " + strings.Repeat("9", 100)).discovery(61); len(d.Error) > 120 {
		t.Fatalf("codice non accorciato: %q", d.Error)
	}
}

func TestScrub(t *testing.T) {
	dir := `C:\Users\Mario Rossi\AppData\Local\Temp\polaris-l2-123`
	msg := `exit status 1: New-NetEventSession : Impossibile creare c:\users\mario rossi\appdata\local\temp\polaris-l2-123\cattura.etl (utente MarioR); D:\Users\anna\x.etl`
	got := scrub(msg, dir, `C:\Users\Mario Rossi\AppData\Local\Temp`, `C:\Users\Mario Rossi`, "MarioR", "", "ab")
	for _, bad := range []string{"Mario", "mario", "anna", "polaris-l2-123", "MarioR"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q rimasto in %q", bad, got)
		}
	}
	if !strings.Contains(got, `…\cattura.etl`) || !strings.Contains(got, `D:\Users\…\x.etl`) {
		t.Fatalf("%q", got)
	}
}

func TestRemoveStaleAndDir(t *testing.T) {
	tmp := t.TempDir()
	old := time.Now().Add(-2 * time.Hour)
	for _, n := range []string{tempPrefix + "vecchia", tempPrefix + "nuova", "altro-vecchia"} {
		p := filepath.Join(tmp, n)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "cattura.etl"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if n != tempPrefix+"nuova" {
			if err := os.Chtimes(p, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, tempPrefix+"file"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if n := removeStale(tmp, time.Now()); n != 1 {
		t.Fatalf("cancellate %d cartelle", n)
	}
	for n, want := range map[string]bool{tempPrefix + "vecchia": false, tempPrefix + "nuova": true, "altro-vecchia": true, tempPrefix + "file": true} {
		if _, err := os.Stat(filepath.Join(tmp, n)); (err == nil) != want {
			t.Errorf("%s: presente=%v", n, err == nil)
		}
	}
	removeDir(filepath.Join(tmp, tempPrefix+"nuova"))
	if _, err := os.Stat(filepath.Join(tmp, tempPrefix+"nuova")); !os.IsNotExist(err) {
		t.Fatal("cartella della cattura non cancellata")
	}
	if removeStale(filepath.Join(tmp, "inesistente"), time.Now()) != 0 {
		t.Fatal("cartella inesistente")
	}
}

// FuzzCaptureOutput: qualunque uscita dello script dà un risultato
// coerente, mai un arresto.
func FuzzCaptureOutput(f *testing.F) {
	f.Add("L2A 12 AA-BB-CC-DD-EE-01 Ethernet\nL2START\nL2F R 12 " + hexUpper(switchLLDP()) + "\nL2END\nL2CLEAN")
	f.Add("L2FAIL start 0x80070005\r\nL2CLEAN")
	f.Add("L2F S\nL2A\nL2EVENTS x")
	f.Fuzz(func(t *testing.T, out string) {
		c := parseCapture(out)
		d := c.discovery(61)
		if len(c.frames) > maxFrames || d.Read == "" {
			t.Fatalf("%+v", d)
		}
	})
}
