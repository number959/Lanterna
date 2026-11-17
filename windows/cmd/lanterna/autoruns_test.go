package main

import (
	"strings"
	"testing"

	"lanterna/internal/scan"
)

func TestPrintAutoruns(t *testing.T) {
	d := &scan.AutorunsData{
		Entries: []scan.AutorunEntry{
			{Category: "logon", Kind: "run", Scope: "user", Name: "Aggiornatore", Location: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, Enabled: true,
				Command: `rundll32.exe "%USERPROFILE%\AppData\Roaming\Fict\agent.dll",Start`,
				File:    &scan.FileFacts{Path: `C:\Windows\System32\rundll32.exe`, Signature: &scan.FileSignature{Status: "valid", Signer: "Microsoft Windows", Microsoft: true}},
				Target:  &scan.FileFacts{Path: `%USERPROFILE%\AppData\Roaming\Fict\agent.dll`, Signature: &scan.FileSignature{Status: "unsigned"}}},
			{Category: "services", Kind: "service", Name: "Fict Service", Start: "auto", Running: true, Account: "system", Unquoted: true, Interceptors: 1, Enabled: true,
				File: &scan.FileFacts{Path: `C:\Program Files\Fict App\svc.exe`, Missing: true}},
			{Category: "tasks", Kind: "task", Name: "Aggiorna", Location: `\Fict\Aggiorna`, Triggers: []string{"logon", "daily"}, RunAs: "system", Highest: true, Hidden: true,
				LastRun: "2026-11-10T12:00:00+01:00", LastResult: "0x80070002", Enabled: false},
			{Category: "browser", Kind: "extension", Name: "Coupon Fict", Browser: "chrome", Profile: 1, Source: "policy", AllSites: true, ExtID: "abc", Enabled: true},
			{Category: "wmi", Kind: "wmi", Name: "Updater", Consumer: "commandline", Bound: true, Namespace: `root\subscription`, Enabled: true},
		},
		Counts: map[string]scan.AutorunCount{
			"logon": {Total: 3, Microsoft: 2}, "services": {Total: 250, Microsoft: 249}, "tasks": {Total: 1}, "browser": {Total: 4}, "wmi": {Total: 1}, "drivers": {Total: 300, Microsoft: 300},
		},
		Denied:  []string{"tasks", "wmi"},
		Partial: true,
	}
	out := capture(t, func() { printAutoruns(d) })
	for _, want := range []string{
		"Lettura senza privilegi di amministratore: attività e servizi visibili a questo utente.",
		"Tempo scaduto prima della fine",
		"Lette solo in parte per i permessi: attività pianificate, sottoscrizioni WMI.",
		"Accesso (chiavi Run, cartelle Esecuzione automatica): 3, di cui 2 di Windows firmate da Microsoft (non elencate)",
		"  - Aggiornatore\n",
		`file: C:\Windows\System32\rundll32.exe [firmato: Microsoft Windows]`,
		`esegue: %USERPROFILE%\AppData\Roaming\Fict\agent.dll [senza firma]`,
		"avvio auto; in esecuzione; account system; percorso con spazi senza virgolette, file intercettori presenti: 1",
		"[FILE MANCANTE]",
		"Driver: 300, di cui 300 di Windows firmate da Microsoft (non elencate)",
		"  - Aggiorna (disattivata)",
		"quando: logon, daily; eseguita come system; con i privilegi più elevati; nascosta; ultima esecuzione 2026-11-10T12:00:00+01:00 esito 0x80070002",
		"Estensioni dei browser: 4, 3 componenti interni dei browser (non elencati)",
		"chrome; profilo 1; origine policy; accesso a tutti i siti; abc",
		"commandline; collegata a un filtro",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Provider di rete") {
		t.Error("categoria non letta mostrata")
	}
}
