package sign

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"lanterna/internal/scan"
)

func TestFolderOf(t *testing.T) {
	for _, k := range []string{"SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "TEMP", "TMP", "USERPROFILE"} {
		t.Setenv(k, "")
	}
	t.Setenv("SystemRoot", `C:\Windows`)
	t.Setenv("ProgramFiles", `C:\Program Files`)
	t.Setenv("ProgramFiles(x86)", `C:\Program Files (x86)`)
	t.Setenv("ProgramData", `C:\ProgramData`)
	t.Setenv("TEMP", `C:\Users\anna\AppData\Local\Temp`)
	prof := `C:\Users\anna`
	for path, want := range map[string]string{
		`C:\Windows\System32\svchost.exe`:                       "windows",
		`c:\windows\explorer.exe`:                               "windows",
		`C:\Program Files\Google\Chrome\Application\chrome.exe`: "programFiles",
		`C:\Program Files (x86)\Steam\steam.exe`:                "programFiles",
		`C:\ProgramData\Vendor\agent.exe`:                       "programData",
		`C:\Users\anna\AppData\Local\Temp\x\setup.exe`:          "temp",
		`C:\Windows\Temp\upd.exe`:                               "temp",
		`C:\Users\anna\Downloads\tool.exe`:                      "downloads",
		`C:\Users\anna\AppData\Roaming\App\app.exe`:             "appData",
		`C:\Users\anna\Desktop\a.exe`:                           "profile",
		`C:\Users\marco\AppData\Local\Prog\p.exe`:               "appData",
		`C:\Users\marco\Downloads\d.exe`:                        "downloads",
		`\\server\share\tool.exe`:                               "network",
		`\\?\C:\Windows\System32\drivers\x.sys`:                 "windows",
		`D:\Giochi\gioco.exe`:                                   "other",
		`C:\Windowsxyz\a.exe`:                                   "other",
	} {
		if got := FolderOf(path, prof); got != want {
			t.Errorf("FolderOf(%q) = %q, atteso %q", path, got, want)
		}
	}
	if FolderOf("", prof) != "" {
		t.Error("percorso vuoto")
	}
	for f, w := range map[string]bool{"appData": true, "temp": true, "windows": false, "programFiles": false, "other": false} {
		if UserWritable(f) != w {
			t.Errorf("UserWritable(%q) != %v", f, w)
		}
	}
}

func TestFactsMissingAndCache(t *testing.T) {
	dir := t.TempDir()
	c := New(dir, func(p string) string { return "S:" + filepath.Base(p) })
	f := c.Facts(context.Background(), filepath.Join(dir, "manca.exe"))
	if !f.Missing || f.Path != "S:manca.exe" {
		t.Fatalf("file mancante: %+v", f)
	}
	p := filepath.Join(dir, "c.exe")
	if err := os.WriteFile(p, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := c.Facts(context.Background(), p)
	b := c.Facts(context.Background(), p)
	if a.Missing || b.Missing || a.Path != b.Path || len(c.cache) != 1 {
		t.Fatalf("cache: %+v %+v %d", a, b, len(c.cache))
	}
	if !IsMicrosoft(&scan.FileSignature{Status: "valid", Signer: "Microsoft Windows", Microsoft: true}) || IsMicrosoft(&scan.FileSignature{Status: "unsigned", Microsoft: true}) || IsMicrosoft(nil) || IsMicrosoft(&scan.FileSignature{Status: "valid", Signer: "Microsoft Windows Hardware Compatibility Publisher"}) {
		t.Error("IsMicrosoft")
	}
}
