package pcinfo

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"lanterna/internal/winevt"
)

func ev(provider string, id int, at string, named map[string]string, data ...string) winevt.Event {
	t, _ := time.Parse(time.RFC3339, at)
	return winevt.Event{Provider: provider, ID: id, Time: t, Named: named, Data: data}
}

const perf = "Microsoft-Windows-Diagnostics-Performance"

func TestBootFrom(t *testing.T) {
	events := []winevt.Event{
		ev(perf, 100, "2026-11-02T08:15:42Z", map[string]string{"BootStartTime": "2026-11-02T08:13:01.5Z", "BootTime": "95210", "MainPathBootTime": "35102", "BootPostBootTime": "60108", "BootNumStartupApps": "14", "BootIsDegradation": "true"}),
		ev(perf, 101, "2026-11-02T08:15:43Z", map[string]string{"Name": `C:\Users\anna\AppData\Local\Vendor\updater.exe`, "FriendlyName": "Vendor Updater", "Version": "3.1", "TotalTime": "12000", "DegradationTime": "9000"}),
		ev(perf, 200, "2026-11-01T19:00:00Z", map[string]string{"ShutdownStartTime": "2026-11-01T18:58:10Z", "ShutdownTime": "110000", "ShutdownIsDegradation": "1"}),
		ev(perf, 101, "2026-10-28T08:00:00Z", map[string]string{"Name": "updater.exe", "TotalTime": "15000", "DegradationTime": "11000"}),
		ev(perf, 203, "2026-10-27T18:00:00Z", map[string]string{"Name": "VendorSvc", "TotalTime": "30000", "DegradationTime": "25000"}),
		ev(perf, 100, "2026-10-28T08:01:00Z", map[string]string{"BootTime": "41000", "MainPathBootTime": "30000", "BootPostBootTime": "11000", "BootIsRebootAfterInstall": "true"}),
		ev(perf, 100, "2026-10-20T08:01:00Z", map[string]string{"BootTime": "0"}),
		ev(perf, 999, "2026-10-20T08:01:00Z", nil),
		ev("Altro", 100, "2026-10-20T08:01:00Z", map[string]string{"BootTime": "5000"}),
	}
	b := BootFrom(events, 90)
	if b.Channel != "ok" || b.Days != 90 || len(b.Boots) != 2 || len(b.Shutdowns) != 1 {
		t.Fatalf("avvio: %+v", b)
	}
	r := b.Boots[0]
	if r.Time != "2026-11-02T08:13:01Z" || r.TotalMs != 95210 || r.PostBootMs != 60108 || r.StartupApps != 14 || !r.Degraded || r.AfterUpdate {
		t.Errorf("primo avvio: %+v", r)
	}
	if !b.Boots[1].AfterUpdate || b.Boots[1].Time != "2026-10-28T08:01:00Z" {
		t.Errorf("secondo avvio: %+v", b.Boots[1])
	}
	if s := b.Shutdowns[0]; s.TotalMs != 110000 || !s.Degraded || s.Time != "2026-11-01T18:58:10Z" {
		t.Errorf("spegnimento: %+v", s)
	}
	if len(b.Slow) != 2 {
		t.Fatalf("componenti lenti: %+v", b.Slow)
	}
	s := b.Slow[0]
	// Raggruppati per nome del file (mai il percorso), con i tempi dell'evento più recente.
	if s.Name != "updater.exe" || s.Count != 2 || s.TotalMs != 12000 || s.DegradationMs != 9000 || s.Kind != "app" || s.Phase != "boot" || s.Friendly != "Vendor Updater" || s.Last != "2026-11-02T08:15:43Z" {
		t.Errorf("componente lento: %+v", s)
	}
	if b.Slow[1].Phase != "shutdown" || b.Slow[1].Kind != "service" {
		t.Errorf("servizio lento allo spegnimento: %+v", b.Slow[1])
	}
	for _, x := range b.Slow {
		if strings.Contains(x.Name, `\`) {
			t.Errorf("percorso nel nome: %q", x.Name)
		}
	}
	if e := BootFrom(nil, 90); e.Boots == nil || len(e.Boots) != 0 {
		t.Error("elenco vuoto non pronto per il JSON")
	}
}

func TestAppsFrom(t *testing.T) {
	crash := func(at, app, module, code, path, pkg string) winevt.Event {
		return ev("Application Error", 1000, at, nil, app, "16.0.1", "0", module, "1.0", "0", code, "0", "0x1", "0x2", path, `C:\x\`+module, "id", pkg, "")
	}
	hang := func(at, app, path string) winevt.Event {
		return ev("Application Hang", 1002, at, nil, app, "2.0", "1234", "0", "0", path, "id", "", "", "Top level window is idle")
	}
	events := []winevt.Event{
		crash("2026-10-30T17:02:11Z", "excel.exe", "mso20win32client.dll", "c0000005", `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE`, ""),
		hang("2026-10-29T10:00:00Z", "Gestionale.exe", `C:\Users\anna\AppData\Local\Gestionale\Gestionale.exe`),
		crash("2026-10-28T09:00:00Z", "EXCEL.EXE", "mso20win32client.dll", "0xC0000005", `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE`, ""),
		crash("2026-10-27T09:00:00Z", "excel.exe", "ntdll.dll", "c0000374", "", ""),
		crash("2026-10-26T09:00:00Z", "explorer.exe", "ntdll.dll", "c0000409", `C:\Windows\explorer.exe`, ""),
		crash("2026-10-25T09:00:00Z", "Calculator.exe", "ucrtbase.dll", "zzz", `C:\Program Files\WindowsApps\Calc\Calculator.exe`, "Microsoft.WindowsCalculator_11.2_x64__8wekyb3d8bbwe"),
		ev("Windows Error Reporting", 1001, "2026-10-30T17:02:12Z", nil, "123", "5", "APPCRASH", "Non disponibile"),
		ev("Windows Error Reporting", 1001, "2026-10-29T10:00:01Z", nil, "456", "5", "AppHangB1"),
		ev("Windows Error Reporting", 1001, "2026-10-28T09:00:01Z", nil, "789", "5", "APPCRASH"),
		ev("Windows Error Reporting", 1001, "2026-10-28T09:00:01Z", nil, "789", "5", `C:\percorso`),
		ev("Altra fonte", 1000, "2026-10-28T09:00:01Z", nil, "x.exe"),
		ev("Application Error", 1000, "2026-10-28T09:00:01Z", nil),
	}
	d := AppsFrom(events, 30, `C:\Users`, `C:\Windows`)
	if d.Crashes != 5 || d.Hangs != 1 || len(d.Apps) != 4 || d.Channel != "ok" {
		t.Fatalf("totali: %+v", d)
	}
	x := d.Apps[0]
	if x.App != "excel.exe" || x.Crashes != 3 || x.Version != "16.0.1" || x.Last != "2026-10-30T17:02:11Z" || x.System || x.UserFolder || x.Store {
		t.Errorf("excel: %+v", x)
	}
	if fmt.Sprint(x.Modules) != "[{mso20win32client.dll 2} {ntdll.dll 1}]" || fmt.Sprint(x.Exceptions) != "[{0xc0000005 2} {0xc0000374 1}]" {
		t.Errorf("moduli ed eccezioni: %v %v", x.Modules, x.Exceptions)
	}
	byName := map[string]int{}
	for i, a := range d.Apps {
		byName[a.App] = i
	}
	if g := d.Apps[byName["Gestionale.exe"]]; g.Hangs != 1 || !g.UserFolder {
		t.Errorf("gestionale: %+v", g)
	}
	if e := d.Apps[byName["explorer.exe"]]; !e.System {
		t.Errorf("explorer: %+v", e)
	}
	if c := d.Apps[byName["Calculator.exe"]]; !c.Store || len(c.Exceptions) != 0 {
		t.Errorf("calcolatrice: %+v", c)
	}
	if fmt.Sprint(d.Reports) != "[{APPCRASH 2 2026-10-30T17:02:12Z} {AppHangB1 1 2026-10-29T10:00:01Z}]" {
		t.Errorf("rapporti: %+v", d.Reports)
	}
}

func TestExceptionAndChannel(t *testing.T) {
	for in, want := range map[string]string{"c0000005": "0xc0000005", "0xC0000409": "0xc0000409", "80000003": "0x80000003", "5": "0x00000005", "": "", "c00000051": "", "zz": ""} {
		if got := ExceptionCode(in); got != want {
			t.Errorf("ExceptionCode(%q) = %q, atteso %q", in, got, want)
		}
	}
	if ChannelState(nil) != "ok" || ChannelState(winevt.ErrDenied) != "denied" || ChannelState(fmt.Errorf("x: %w", winevt.ErrNoChannel)) != "missing" || ChannelState(errors.New("x")) != "error" {
		t.Error("ChannelState")
	}
}

func TestReliability(t *testing.T) {
	h, err := parseHealth("AVVISO\r\n" + `{"rel":[{"t":"2026-11-01T10:00:00.0000000Z","i":7.81},{"t":"2026-11-01T22:00:00Z","i":6.04},{"t":"2026-10-31T09:00:00Z","i":8.2},{"t":"x","i":5},{"t":"2026-10-30T09:00:00Z","i":42}],` +
		`"relrec":[{"source":"Application Error","id":1000,"product":"Microsoft Excel","count":4,"last":"2026-11-01T21:00:00.0000000Z"},` +
		`{"source":"Microsoft-Windows-WindowsUpdateClient","id":20,"product":"Aggiornamento cumulativo (KB5068865)","count":2,"last":"2026-10-31T09:00:00Z"},` +
		`{"source":"MsiInstaller","id":11707,"product":"C:\\Users\\anna\\Downloads\\setup.msi","count":1,"last":"2026-10-30T09:00:00Z"},` +
		`{"source":"","id":1,"count":3}],"errors":{}}`)
	if err != nil {
		t.Fatal(err)
	}
	on := true
	r := ReliabilityFrom(h, &on, `C:\Users\anna`)
	if !r.Available || r.Index == nil || *r.Index != 6 || r.IndexAt != "2026-11-01T22:00:00Z" || r.Reason != "" {
		t.Fatalf("indice: %+v", r)
	}
	if fmt.Sprint(r.Series) != "[{2026-10-31 8.2} {2026-11-01 6}]" {
		t.Errorf("serie: %v", r.Series)
	}
	if len(r.Records) != 3 || r.Records[0].Category != "app-crash" || r.Records[1].Category != "update-failed" || r.Records[2].Category != "install" {
		t.Fatalf("record: %+v", r.Records)
	}
	if r.Records[2].Product != `%USERPROFILE%\Downloads\setup.msi` || r.Records[0].Last != "2026-11-01T21:00:00Z" {
		t.Errorf("prodotto senza cartella dell'utente: %+v", r.Records[2])
	}
	off := false
	empty, _ := parseHealth(`{"rel":[],"relrec":[],"errors":{}}`)
	if x := ReliabilityFrom(empty, &off, ""); x.Available || x.Reason != "disabled" || x.Index != nil {
		t.Errorf("disattivato: %+v", x)
	}
	if x := ReliabilityFrom(empty, nil, ""); x.Reason != "no-data" {
		t.Errorf("senza dati: %+v", x)
	}
	failed, _ := parseHealth(`{"errors":{"rel":"Classe non valida"}}`)
	if x := ReliabilityFrom(failed, nil, ""); x.Reason != "error" {
		t.Errorf("errore: %+v", x)
	}
	if _, err := parseHealth("niente"); err == nil {
		t.Error("uscita senza JSON accettata")
	}
	for _, c := range []struct {
		src  string
		id   int
		want string
	}{{"Application Hang", 1002, "app-hang"}, {"Microsoft-Windows-WER-SystemErrorReporting", 1001, "windows-failure"}, {"EventLog", 6008, "shutdown"}, {"MsiInstaller", 11708, "install-failed"}, {"Microsoft-Windows-WindowsUpdateClient", 19, "update"}, {"Qualcosa", 1, "other"}} {
		if got := relCategory(c.src, c.id); got != c.want {
			t.Errorf("relCategory(%s, %d) = %s", c.src, c.id, got)
		}
	}
}

// Eventi 109 e 202: per i dispositivi Name è l'identificativo d'istanza, con
// il numero di serie o l'indirizzo Bluetooth. Nel rapporto restano solo
// l'enumeratore del bus e il nome con le regole di Gestione dispositivi.
func TestBootSlowDevicesWithoutInstanceIDs(t *testing.T) {
	at := "2026-11-01T08:00:00Z"
	events := []winevt.Event{
		ev(perf, 202, at, map[string]string{"Name": `USB\VID_0BDA&PID_0129\20100201396000000`, "FriendlyName": "Realtek USB 2.0 Card Reader", "TotalTime": "900", "DegradationTime": "600"}),
		ev(perf, 109, at, map[string]string{"Name": `BTHENUM\{0000110B-0000-1000-8000-00805F9B34FB}_LOCALMFG&0002\7&1B2C3D4E&0&001A7DDA7113_C00000000`, "FriendlyName": "AirPods di Anna", "TotalTime": "1200", "DegradationTime": "800"}),
		ev(perf, 109, at, map[string]string{"Name": `\\?\strano`, "TotalTime": "500", "DegradationTime": "300"}),
	}
	b := BootFrom(events, 90)
	if len(b.Slow) != 3 {
		t.Fatalf("lenti: %+v", b.Slow)
	}
	for _, s := range b.Slow {
		j := s.Name + "|" + s.Friendly
		for _, bad := range []string{"2010020139", "001A7DDA7113", "Anna", `\`, "VID_"} {
			if strings.Contains(j, bad) {
				t.Errorf("%q contiene %q", j, bad)
			}
		}
	}
	got := map[string]string{}
	for _, s := range b.Slow {
		got[s.Name] = s.Friendly
	}
	if got["USB"] != "Realtek USB 2.0 Card Reader" || got["BTHENUM"] != "Dispositivo Bluetooth" || got["dispositivo"] != "" {
		t.Errorf("nomi: %v", got)
	}
}
