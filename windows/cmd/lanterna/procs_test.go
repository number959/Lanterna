package main

import (
	"strings"
	"testing"

	"lanterna/internal/scan"
)

func TestPrintProcs(t *testing.T) {
	d := &scan.ProcessesData{
		At: "2026-11-17T10:00:00Z", Unreadable: 3, Partial: true, ConnsRead: true,
		Items: []scan.ProcessDetail{
			{PID: 4, Name: "System", Listen: []scan.ListenPort{{Proto: "tcp", Port: 445, Scope: "all"}, {Proto: "tcp", Port: 445, Scope: "all", IPv6: true}}},
			{PID: 812, ParentPID: 700, Name: "svchost.exe", Owner: "system", Arch: "x64", MemoryMB: 12.5, CPUPct: scan.Ptr(0.0), Services: []string{"Dnscache", "nsi"},
				File: &scan.FileFacts{Path: `C:\Windows\System32\svchost.exe`, Folder: "windows", Company: "Microsoft Corporation", Description: "Processo host per i servizi di Windows", Version: "10.0.26100.1",
					Signature: &scan.FileSignature{Status: "valid", Signer: "Microsoft Windows", Catalog: true, Microsoft: true}}},
			{PID: 1300, Name: "antivirus.exe", Access: "none", Owner: "unknown"},
			{PID: 2000, Name: "strumento.exe", Owner: "self", Elevated: true,
				File:   &scan.FileFacts{Path: `%USERPROFILE%\Downloads\strumento.exe`, Folder: "downloads", Signature: &scan.FileSignature{Status: "unsigned", Code: "0x800B0100"}},
				Listen: []scan.ListenPort{{Proto: "tcp", Port: 8080, Scope: "all"}, {Proto: "udp", Port: 5353, Scope: "local"}},
				Conns:  &scan.ConnSummary{Internet: 3, LAN: 1, RemotePorts: []scan.PortCount{{Port: 443, Count: 3}, {Port: 445, Count: 1}}}},
			{PID: 2100, Name: "alterato.exe", Owner: "self", File: &scan.FileFacts{Path: `D:\alterato.exe`, Folder: "removable", Signature: &scan.FileSignature{Status: "tampered", Signer: "Esempio Srl", Code: "0x80096010"}}},
			{PID: 3000, Name: "polaris.exe", Polaris: true, Owner: "self", File: &scan.FileFacts{Path: `%USERPROFILE%\Desktop\polaris.exe`, Folder: "profile"}},
		},
	}
	out := capture(t, func() { printProcs(d) })
	for _, want := range []string{
		"Processi in esecuzione: 6\nLetti senza i diritti di amministratore.",
		"Non leggibili senza amministratore: 3 (se ne conosce solo il nome).",
		"Lettura non finita in tempo",
		"Firme dei programmi: 1 di Microsoft, 0 di altri produttori, 1 senza firma, 1 da controllare.",
		"System (PID 4)\n  In ascolto: TCP 445 (tutte le interfacce), TCP 445 IPv6 (tutte le interfacce)",
		"svchost.exe (PID 812, padre 700) · sistema, x64, 12,5 MB, CPU 0,0 %",
		"  Servizi: Dnscache, nsi",
		`  File: C:\Windows\System32\svchost.exe (Windows)`,
		"  Firma verificata: Microsoft Windows (catalogo di Windows), componente Microsoft",
		"  Dichiarato dal file: Processo host per i servizi di Windows · Microsoft Corporation · versione 10.0.26100.1",
		"antivirus.exe (PID 1300) · account non leggibile, non apribile senza amministratore",
		"strumento.exe (PID 2000) · tu, amministratore",
		"  Nessuna firma digitale\n",
		"  In ascolto: TCP 8080 (tutte le interfacce), UDP 5353 (solo questo PC)",
		"  Connessioni: 3 verso Internet, 1 in rete locale; porte remote 443×3, 445×1",
		`  File: D:\alterato.exe (unità rimovibile)`,
		"  File modificato dopo la firma: Esempio Srl [0x80096010]",
		"polaris.exe (PID 3000) · STARNET Polaris, tu",
		"  Firma non verificata",
		"non termina processi e non chiude connessioni",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("manca %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Connessioni di rete non lette") {
		t.Error("connessioni lette")
	}

	// Da amministratore un processo non apribile non lo diventa con
	// l'amministratore: è protetto da Windows.
	d.Elevated = true
	out = capture(t, func() { printProcs(d) })
	for _, want := range []string{
		"Letti come amministratore.",
		"Non apribili: 3, processi protetti da Windows (se ne conosce solo il nome).",
		"antivirus.exe (PID 1300) · account non leggibile, non apribile: processo protetto da Windows",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("da amministratore manca %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "senza amministratore") {
		t.Errorf("da amministratore il testo parla di «senza amministratore»:\n%s", out)
	}
}
