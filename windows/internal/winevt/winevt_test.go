package winevt

import (
	"testing"
	"time"
)

// Esempi di XML con la struttura che restituisce EvtRender: un evento con
// manifesto (valori con nome) e uno classico (valori senza nome). Nome del
// computer e utente sono presenti, come nei registri veri, e vanno ignorati.
const bootXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Diagnostics-Performance' Guid='{CFC18EC0-96B1-4EBA-961B-622CAEE05B0A}'/><EventID>100</EventID><Version>2</Version><Level>2</Level><Task>4002</Task><Opcode>34</Opcode><Keywords>0x8000000000010000</Keywords><TimeCreated SystemTime='2026-11-02T08:15:42.1234567Z'/><EventRecordID>1041</EventRecordID><Correlation ActivityID='{11111111-2222-3333-4444-555555555555}'/><Execution ProcessID='3412' ThreadID='4180'/><Channel>Microsoft-Windows-Diagnostics-Performance/Operational</Channel><Computer>PC-DI-MARIO</Computer><Security UserID='S-1-5-19'/></System><EventData><Data Name='BootTsVersion'>2</Data><Data Name='BootStartTime'>2026-11-02T08:13:01.500000000Z</Data><Data Name='BootTime'>95210</Data><Data Name='MainPathBootTime'>35102</Data><Data Name='BootPostBootTime'>60108</Data><Data Name='BootNumStartupApps'>14</Data><Data Name='BootIsDegradation'>false</Data></EventData></Event>`

const crashXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Application Error'/><EventID Qualifiers='0'>1000</EventID><Version>0</Version><Level>2</Level><Task>100</Task><Opcode>0</Opcode><Keywords>0x80000000000000</Keywords><TimeCreated SystemTime='2026-10-30T17:02:11.0000000Z'/><EventRecordID>5512</EventRecordID><Correlation/><Execution ProcessID='0' ThreadID='0'/><Channel>Application</Channel><Computer>PC-DI-MARIO</Computer><Security/></System><EventData><Data>excel.exe</Data><Data>16.0.17928.20156</Data><Data>66f2a1b0</Data><Data>mso20win32client.dll</Data><Data>0.0.0.0</Data><Data>00000000</Data><Data>c0000005</Data><Data>0000000000a1b2c3</Data><Data>0x2a10</Data><Data>0x1db2b1f8a2c3d4e</Data><Data>C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE</Data><Data>C:\Program Files\Common Files\Microsoft Shared\Office16\mso20win32client.dll</Data><Data>8a1b2c3d-0000-0000-0000-000000000000</Data><Data></Data><Data></Data></EventData></Event>`

func TestParseXML(t *testing.T) {
	e, err := ParseXML([]byte(bootXML))
	if err != nil {
		t.Fatal(err)
	}
	if e.Provider != "Microsoft-Windows-Diagnostics-Performance" || e.ID != 100 || e.Level != 2 {
		t.Errorf("intestazione: %+v", e)
	}
	if !e.Time.Equal(time.Date(2026, 11, 2, 8, 15, 42, 123456700, time.UTC)) {
		t.Errorf("ora: %v", e.Time)
	}
	if e.Get("BootTime", 2) != "95210" || e.Get("Assente", 0) != "" || len(e.Data) != 7 {
		t.Errorf("valori con nome: %v", e.Named)
	}
	c, err := ParseXML([]byte(crashXML))
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != 1000 || c.Provider != "Application Error" || c.Named != nil || len(c.Data) != 15 {
		t.Fatalf("evento classico: %+v", c)
	}
	if c.Get("AppName", 0) != "excel.exe" || c.Get("ExceptionCode", 6) != "c0000005" || c.Get("PackageFullName", 13) != "" || c.Get("X", 20) != "" {
		t.Errorf("valori per posizione: %q", c.Data)
	}
	if _, err := ParseXML([]byte("<Event><System><EventID>x</EventID></System></Event>")); err == nil {
		t.Error("evento senza codice accettato")
	}
	if _, err := ParseXML([]byte("non xml")); err == nil {
		t.Error("testo non XML accettato")
	}
}

func TestXPath(t *testing.T) {
	got := XPath([]int{1000, 1002}, 30, "Application Error", "Application Hang")
	want := "*[System[Provider[@Name='Application Error' or @Name='Application Hang'] and (EventID=1000 or EventID=1002) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]"
	if got != want {
		t.Errorf("XPath:\n%s\n%s", got, want)
	}
	if XPath(nil, 0) != "*" || XPath([]int{100}, 0) != "*[System[(EventID=100)]]" {
		t.Error("XPath senza filtri")
	}
	if XPath(nil, 1, "x'y") != "*[System[Provider[@Name='xy'] and TimeCreated[timediff(@SystemTime) <= 86400000]]]" {
		t.Error("apice nel nome della fonte")
	}
}
