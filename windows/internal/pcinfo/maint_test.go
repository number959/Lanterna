package pcinfo

import (
	"fmt"
	"testing"

	"lanterna/internal/scan"
	"lanterna/internal/winevt"
)

func TestMemDiagFrom(t *testing.T) {
	events := []winevt.Event{
		ev(MemDiagSchedule, 1001, "2026-10-20T08:00:00Z", nil),
		{Provider: MemDiagResults, ID: 1201, Level: 4, Time: ev("", 0, "2026-09-02T09:00:00Z", nil).Time},
		{Provider: MemDiagResults, ID: 1202, Level: 2, Time: ev("", 0, "2026-03-02T09:00:00Z", nil).Time},
		ev("Altro", 1201, "2026-09-02T09:00:00Z", nil),
	}
	m := MemDiagFrom(events, 365)
	if m.Days != 365 || len(m.Results) != 2 || m.Results[0].Errors || !m.Results[1].Errors || m.Results[0].Time != "2026-09-02T09:00:00Z" || m.LastScheduled != "2026-10-20T08:00:00Z" {
		t.Errorf("esiti: %+v", m)
	}
	if e := MemDiagFrom(nil, 365); e.Results == nil || e.LastScheduled != "" {
		t.Errorf("vuoto: %+v", e)
	}
}

func TestFsChecksFrom(t *testing.T) {
	events := []winevt.Event{
		ev("Wininit", 1001, "2026-10-11T07:59:00Z", nil, "\r\n\r\nControllo del file system in C:\r\nIl tipo del file system è NTFS.\r\nC:\\Users\\anna\\Documenti\\file.docx recuperato"),
		ev("Chkdsk", 26214, "2026-10-05T10:00:00Z", nil, "Chkdsk è stato eseguito in modalità di analisi su un volume snapshot.\r\nD:\\..."),
		ev("Wininit", 1000, "2026-10-01T10:00:00Z", nil, "C:"),
		ev("Altro", 1001, "2026-10-01T10:00:00Z", nil, "C:"),
		ev("Chkdsk", 26212, "2026-10-01T10:00:00Z", nil),
	}
	got := FsChecksFrom(events)
	if fmt.Sprint(got) != "[{2026-10-11T07:59:00Z wininit 1001 C:} {2026-10-05T10:00:00Z chkdsk 26214 D:} {2026-10-01T10:00:00Z chkdsk 26212 }]" {
		t.Errorf("controlli: %+v", got)
	}
}

func TestUpdateHistory(t *testing.T) {
	list := []psUpdate{
		{Title: "Aggiornamento cumulativo per Windows 11 Version 23H2 per sistemi basati su x64 (KB5068865)", Date: "2026-10-08T03:12:00Z", Op: 1, RC: 4, HR: "0x800F081F", ID: "{11111111-AAAA-0000-0000-000000000000}"},
		{Title: "Aggiornamento dell'intelligence di sicurezza per Microsoft Defender Antivirus - KB2267602 (Versione 1.419.98.0)", Date: "2026-10-12T06:10:00Z", Op: 1, RC: 2, HR: "0x00000000"},
		{Title: "Intel - System - 10.1.1.44", Date: "2026-09-20T03:00:00Z", Op: 1, RC: 2, HR: "0x00000000"},
		{Title: "Windows 11, versione 24H2", Date: "2026-09-15T03:00:00Z", Op: 1, RC: 4, HR: "0xC1900101"},
		{Title: "Strumento di rimozione malware", Date: "2026-09-10T03:00:00Z", Op: 2, RC: 9, HR: ""},
	}
	got := UpdateHistoryFrom(list)
	if len(got) != 5 || got[0].Kind != "definition" || got[0].KB != "KB2267602" || got[0].Result != "succeeded" || got[0].HResult != "" {
		t.Fatalf("prima voce: %+v", got)
	}
	q := got[1]
	if q.Kind != "quality" || q.KB != "KB5068865" || q.Result != "failed" || q.HResult != "0x800F081F" || q.UpdateID != "11111111-aaaa-0000-0000-000000000000" || q.Operation != "install" {
		t.Errorf("cumulativo: %+v", q)
	}
	if got[2].Kind != "driver" || got[3].Kind != "feature" || got[3].HResult != "0xC1900101" {
		t.Errorf("driver e funzionalità: %+v %+v", got[2], got[3])
	}
	if got[4].Operation != "uninstall" || got[4].Result != "notStarted" || got[4].Kind != "other" {
		t.Errorf("ultima: %+v", got[4])
	}
	long := UpdateHistoryFrom([]psUpdate{{Title: string(make([]rune, 0)) + fmt.Sprintf("%0200d", 7)}})
	if r := []rune(long[0].Title); len(r) != 161 {
		t.Errorf("titolo non accorciato: %d", len(r))
	}
	for k, want := range map[string]string{"": "other", "KB5068865": "quality"} {
		if UpdateKind("Titolo", k, "") != want {
			t.Errorf("UpdateKind(%q)", k)
		}
	}
	if UpdateKind("Aggiornamento delle funzionalità a Windows 10, versione 22H2", "", "") != "feature" {
		t.Error("aggiornamento delle funzionalità")
	}
	// Lo Strumento di rimozione malware e gli aggiornamenti di altri prodotti
	// non sono aggiornamenti di qualità di Windows (né di funzionalità: un
	// titolo .NET contiene "Windows 11, version 23H2").
	for title, want := range map[string]string{
		"Windows Malicious Software Removal Tool x64 - v5.131 (KB890830)":                                                  "other",
		"Strumento di rimozione malware di Windows x64 - v5.131 (KB890830)":                                                "other",
		"2024-01 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 23H2 for x64 (KB5034467)":      "other",
		"Aggiornamento cumulativo 2024-01 per .NET Framework 3.5 e 4.8.1 per Windows 11, version 23H2 per x64 (KB5034467)": "other",
		"Microsoft Office: aggiornamento della sicurezza (KB5002700)":                                                      "other",
		"2026-10 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5066835)":                          "quality",
		"Aggiornamento cumulativo 2026-10 per Windows 11 Version 24H2 per sistemi basati su x64 (KB5066835)":               "quality",
	} {
		if got := UpdateKind(title, kbRe.FindString(title), ""); got != want {
			t.Errorf("UpdateKind(%q) = %q, atteso %q", title, got, want)
		}
	}
}

func TestMergeMaintAndDetails(t *testing.T) {
	h, err := parseHealth(`{"wu":[{"title":"x (KB5068865)","date":"2026-10-08T03:12:00Z","op":1,"rc":2,"hr":"0x00000000","id":"a"}],"wures":{"install":"2026-10-12T06:10:00Z","search":"2026-10-12T06:00:00Z"},"wureboot":true,"vols":[{"letter":"C","health":2},{"letter":"D","health":7}],"errors":{}}`)
	if err != nil {
		t.Fatal(err)
	}
	pc := &scan.PcData{Volumes: []scan.Volume{{Letter: "C:"}, {Letter: "D:"}}, Updates: &scan.UpdateInfo{RebootReasons: []string{"componenti di Windows"}}}
	mergeMaint(pc, h)
	u := pc.Updates
	if len(u.History) != 1 || u.LastSuccess != "2026-10-12T06:10:00Z" || u.LastSearch == "" || !u.PendingReboot || fmt.Sprint(u.RebootReasons) != "[componenti di Windows Windows Update]" {
		t.Errorf("aggiornamenti: %+v", u)
	}
	if pc.Volumes[0].Health != "spotfix" || pc.Volumes[1].Health != "" {
		t.Errorf("volumi: %+v", pc.Volumes)
	}
	failed, _ := parseHealth(`{"errors":{"wu":"0x80070422"}}`)
	pc2 := &scan.PcData{}
	mergeMaint(pc2, failed)
	if pc2.Updates.History != nil || pc2.Updates.HistoryError != "0x80070422" {
		t.Errorf("errore: %+v", pc2.Updates)
	}
	for in, want := range map[string]string{"c:": "C:", "D:": "D:", `\Device\HarddiskVolume3`: "", "C:\\Users\\anna": "", "": ""} {
		if FsDetail(in) != want {
			t.Errorf("FsDetail(%q) = %q", in, FsDetail(in))
		}
	}
	for v, want := range map[int]string{0: "healthy", 1: "scan", 2: "spotfix", 3: "repair", 9: ""} {
		if VolumeHealth(v) != want {
			t.Errorf("VolumeHealth(%d)", v)
		}
	}
	if ClassifyEvent("Microsoft-Windows-Ntfs", 130) != "fs-repaired" || ClassifyEvent("Ntfs", 140) != "fs-flush" || ClassifyEvent("Ntfs", 50) != "fs-flush" || ClassifyEvent("Altro", 50) != "" {
		t.Error("eventi del file system")
	}
}
