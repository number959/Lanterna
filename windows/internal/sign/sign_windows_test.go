//go:build windows

package sign

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Prova su Windows vero (passo della CI «Prove native dell'agente su
// Windows reale»): componenti di Windows firmati da Microsoft, file non
// firmati creati al volo, una copia alterata di un file con firma incorporata.
func TestVerifyWindows(t *testing.T) {
	ctx := context.Background()
	win := os.Getenv("SystemRoot")
	if win == "" {
		win = `C:\Windows`
	}
	checked := 0
	for _, p := range []string{filepath.Join(win, "explorer.exe"), filepath.Join(win, "System32", "notepad.exe"), filepath.Join(win, "System32", "svchost.exe")} {
		np := nativePath(p)
		if _, err := os.Stat(np); err != nil {
			t.Logf("%s: assente (%v)", p, err)
			continue
		}
		start := time.Now()
		s := verify(ctx, np)
		c, d, v := versionInfo(np)
		t.Logf("%s: %+v in %v; %q %q %q", p, s, time.Since(start), c, d, v)
		if s == nil || s.Status != "valid" || !s.Microsoft || !strings.HasPrefix(s.Signer, "Microsoft") {
			t.Errorf("%s: firma di Microsoft non riconosciuta: %+v", p, s)
		}
		if c == "" || d == "" || v == "" {
			t.Errorf("%s: informazioni di versione non lette: %q %q %q", p, c, d, v)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("nessun componente di Windows trovato")
	}

	// File non firmati: l'eseguibile di questa prova (Go non lo firma) e un testo.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	txt := filepath.Join(dir, "nota.txt")
	if err := os.WriteFile(txt, []byte("nessuna firma qui\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{exe, txt} {
		s := verify(ctx, p)
		t.Logf("%s: %+v", p, s)
		if s == nil || s.Status != "unsigned" || s.Microsoft || s.Catalog || s.Signer != "" || s.Code == "" {
			t.Errorf("%s: atteso «unsigned»: %+v", p, s)
		}
	}
	if s := verify(ctx, filepath.Join(dir, "manca.exe")); s == nil || s.Status != "unreadable" {
		t.Errorf("file mancante: %+v", s)
	}

	// Firma incorporata alterata: copia di un file firmato con un byte cambiato.
	var src string
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `PowerShell\7\pwsh.exe`),
		filepath.Join(win, "System32", "ntoskrnl.exe"),
	} {
		np := nativePath(p)
		if s := verify(ctx, np); s != nil && s.Status == "valid" && !s.Catalog {
			src = np
			break
		}
	}
	if src == "" {
		t.Log("nessun file con firma incorporata tra quelli noti: prova della copia alterata saltata")
	} else {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		b[len(b)/3] ^= 0xFF
		bad := filepath.Join(dir, "alterato.exe")
		if err := os.WriteFile(bad, b, 0o644); err != nil {
			t.Fatal(err)
		}
		s := verify(ctx, bad)
		t.Logf("copia alterata di %s: %+v", src, s)
		if s == nil || s.Status != "tampered" || s.Microsoft || s.Code != "0x80096010" {
			t.Errorf("copia alterata: attesa «tampered»: %+v", s)
		}
	}

	// Checker: cartella, cache e percorso esportato.
	c := New(os.Getenv("USERPROFILE"), func(p string) string { return "S:" + filepath.Base(p) })
	f := c.Facts(ctx, filepath.Join(win, "explorer.exe"))
	if f.Folder != "windows" || f.Path != "S:explorer.exe" || !IsMicrosoft(f.Signature) || f.Company == "" {
		t.Errorf("Facts: %+v %+v", f, f.Signature)
	}
}
