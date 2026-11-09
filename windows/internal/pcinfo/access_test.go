package pcinfo

import (
	"fmt"
	"testing"
	"time"

	"lanterna/internal/scan"
)

func TestAccountsFrom(t *testing.T) {
	users := []rawUser{
		{RID: 1001, Flags: 0x0200},                     // utente, attivo
		{RID: 500, Flags: 0x0200 | ufDontExpirePasswd}, // Administrator integrato attivo
		{RID: 501, Flags: 0x0200 | ufAccountDisable},   // Guest disattivato
		{RID: 1002, Flags: 0x0200 | ufPasswdNotReqd},   // password non richiesta
		{RID: 503, Flags: 0x0200 | ufAccountDisable},   // DefaultAccount
		{RID: 1003, Flags: 0x0200 | ufLockout | ufAccountDisable},
	}
	a := AccountsFrom(users, map[int]bool{500: true, 1001: true, 1003: true}, 2, 1001, true)
	if len(a.Local) != 6 || a.Local[0].RID != 500 || a.Local[0].Kind != "builtin-admin" || !a.Local[0].Enabled || !a.Local[0].Admin || !a.Local[0].PasswordNeverExpires {
		t.Fatalf("account: %+v", a.Local)
	}
	byRID := map[int]scan.LocalAccount{}
	for _, l := range a.Local {
		byRID[l.RID] = l
	}
	if g := byRID[501]; g.Kind != "guest" || g.Enabled {
		t.Errorf("guest: %+v", g)
	}
	if u := byRID[1001]; !u.Current || !u.Admin || u.Kind != "user" {
		t.Errorf("utente corrente: %+v", u)
	}
	if u := byRID[1002]; !u.PasswordNotRequired || u.Admin {
		t.Errorf("senza password richiesta: %+v", u)
	}
	if u := byRID[1003]; !u.LockedOut || u.Enabled {
		t.Errorf("bloccato: %+v", u)
	}
	if a.Admins == nil || a.Admins.Members != 5 || a.Admins.LocalEnabled != 2 || a.Admins.Other != 2 || a.CurrentIsAdmin == nil || !*a.CurrentIsAdmin {
		t.Errorf("amministratori: %+v %v", a.Admins, a.CurrentIsAdmin)
	}
	b := AccountsFrom(nil, nil, 0, 0, false)
	if b.Local == nil || b.Admins != nil || b.CurrentIsAdmin != nil {
		t.Errorf("senza dati: %+v", b)
	}
}

func TestPrinterHelpers(t *testing.T) {
	if got := fmt.Sprint(PrinterFlags(0x2 | 0x80 | 0x20000)); got != "[error offline toner-low]" {
		t.Errorf("PrinterFlags: %s", got)
	}
	if PrinterFlags(0) != nil {
		t.Error("nessuno stato")
	}
	cases := map[[2]string]string{
		{"PORTPROMPT:", "Microsoft Print To PDF"}:             "virtual",
		{"nul:", "Microsoft XPS Document Writer v4"}:          "virtual",
		{"SHRFAX:", "Microsoft Shared Fax Driver"}:            "virtual",
		{"WSD-1a2b3c4d-0000-0000-0000-000000000000", "HP"}:    "wsd",
		{"USB001", "Brother HL-L2350DW series"}:               "usb",
		{"192.168.1.50", "HP Universal Printing PCL 6"}:       "tcp",
		{"IP_10.0.0.20", "Kyocera"}:                           "tcp",
		{"http://print.local:631/ipp", "Microsoft IPP Class"}: "tcp",
		{"LPT1:", "Generic / Text Only"}:                      "other",
	}
	for in, want := range cases {
		if got := PrinterKind(in[0], in[1]); got != want {
			t.Errorf("PrinterKind(%q, %q) = %q, atteso %q", in[0], in[1], got, want)
		}
	}
	now := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	if f, s, age := JobState(0, now.Add(-20*time.Minute), now); f || !s || age != 20 {
		t.Errorf("fermo: %v %v %d", f, s, age)
	}
	if f, s, _ := JobState(jobPrinting, now.Add(-30*time.Minute), now); f || s {
		t.Error("in stampa non è fermo")
	}
	if f, _, _ := JobState(jobError, now, now); !f {
		t.Error("errore")
	}
}

func TestProtectionFrom(t *testing.T) {
	five := 5
	e := EncryptionFrom([]psEncVolume{
		{Letter: "C:", Type: 0, Conv: 1, Pct: 100, Flags: 1, Prot: 1, Method: 6, KP: []int{1, 3}, KPOk: true, RID: "1A2B3C4D", Suspend: nil},
		{Letter: "D", Type: 1, Conv: 0, Pct: 0, Prot: 0, Method: 0, KPOk: true},
		{Letter: "E:", Type: 2, Conv: 4, Pct: 37, Prot: 2, Method: 4294967295, KPOk: false, RID: "zz", Suspend: &five},
		{Letter: "", Type: 1},
	}, "", true)
	if e.Read != "ok" || len(e.Volumes) != 3 {
		t.Fatalf("cifratura: %+v", e)
	}
	c := e.Volumes[0]
	if c.Kind != "os" || c.Conversion != "encrypted" || c.Protection != "on" || c.Method != "xts-aes128" || fmt.Sprint(c.Protectors) != "[tpm recovery-password]" || c.RecoveryKeyID != "1A2B3C4D" || !c.UsedSpaceOnly || *c.Percent != 100 {
		t.Errorf("C: %+v", c)
	}
	if d := e.Volumes[1]; d.Letter != "D:" || d.Protectors == nil || len(d.Protectors) != 0 || d.Conversion != "decrypted" || d.Protection != "off" {
		t.Errorf("D: %+v", d)
	}
	if x := e.Volumes[2]; x.Protectors != nil || x.Method != "unknown" || x.Conversion != "encrypt-paused" || x.RecoveryKeyID != "" || *x.SuspendCount != 5 || x.Protection != "unknown" {
		t.Errorf("E: %+v", x)
	}
	for msg, want := range map[string]string{"AccessDenied": "denied", "0x80041003": "denied", "InvalidNamespace": "absent", "0x8004100E": "absent", "Failed": "error"} {
		if got := EncryptionFrom(nil, msg, false).Read; got != want {
			t.Errorf("errore %q: %s", msg, got)
		}
	}
	r := RestoreFrom([]psRestore{{T: "2026-10-03T08:00:00Z", Type: 17}, {T: "2026-09-01T08:00:00Z", Type: 0}, {T: "x", Type: 1}}, "", true, false)
	if r.Read != "ok" || r.Count != 2 || r.Newest != "2026-10-03T08:00:00Z" || r.NewestType != "windows-update" || r.Oldest != "2026-09-01T08:00:00Z" {
		t.Errorf("punti di ripristino: %+v", r)
	}
	if RestoreFrom(nil, "", true, true).Read != "unsupported" || RestoreFrom(nil, "AccessDenied", false, false).Read != "denied" || RestoreFrom(nil, "InvalidClass", false, false).Read != "unsupported" {
		t.Error("stati dei punti di ripristino")
	}
	b := ImageBackupFrom([]psBackupEvent{{ID: 4, T: "2026-09-20T22:00:00Z"}, {ID: 49, T: "2026-10-05T22:00:00Z"}, {ID: 520, T: "2026-10-01T22:00:00Z"}, {ID: 14, T: "2026-10-05T21:00:00Z"}}, "", true, 90)
	if b.LastSuccess != "2026-09-20T22:00:00Z" || b.LastFailure != "2026-10-05T22:00:00Z" || b.FailureID != 49 || b.Failures != 2 || b.Days != 90 {
		t.Errorf("backup: %+v", b)
	}
	for v, want := range map[int]string{0: "app-install", 10: "driver-install", 12: "settings", 13: "cancelled", 99: "other"} {
		if RestoreTypeName(v) != want {
			t.Errorf("RestoreTypeName(%d)", v)
		}
	}
	for v, want := range map[int]string{2: "startup-key", 4: "tpm-pin", 8: "password", 10: "other"} {
		if ProtectorName(v) != want {
			t.Errorf("ProtectorName(%d)", v)
		}
	}
	pc := &scan.PcData{OS: &scan.PcOS{Server: true}}
	h, _ := parseHealth(`{"bl":[{"letter":"C","type":0,"conv":1,"pct":100,"prot":1,"method":7,"kp":[1],"kpOk":true}],"wb":[],"errors":{"rp":"InvalidClass"}}`)
	mergeProtection(pc, h)
	if pc.Encryption.Volumes[0].Method != "xts-aes256" || pc.Backup.RestorePoints.Read != "unsupported" || pc.Backup.ImageBackup.Read != "ok" {
		t.Errorf("unione: %+v %+v", pc.Encryption, pc.Backup)
	}
}
