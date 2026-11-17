package sign

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatusOf(t *testing.T) {
	for code, want := range map[uint32]string{
		0:                        "valid",
		trustENoSignature:        "unsigned",
		trustESubjectFormUnknown: "unsigned",
		trustEBadDigest:          "tampered",
		certERevoked:             "revoked",
		cryptERevoked:            "revoked",
		trustEExplicitDistrust:   "distrusted",
		certEExpired:             "expired",
		certEUntrustedRoot:       "untrustedRoot",
		certEChaining:            "untrustedRoot",
		certEUntrustedCA:         "untrustedRoot",
		certEUntrustedTestRoot:   "untrustedRoot",
		certEWrongUsage:          "wrongUsage",
		cryptESecuritySettings:   "policy",
		trustETimeStamp:          "invalid",
		trustECertSignature:      "invalid",
		trustENoSignerCert:       "invalid",
		trustEMalformedSignature: "invalid",
		trustESubjectNotTrusted:  "invalid",
		certERevocationFailure:   "valid",
		cryptERevocationOffline:  "valid",
		cryptENoRevocationCheck:  "valid",
		cryptEFileError:          "unreadable",
		0x80070005:               "unreadable", // accesso negato
		0x80070020:               "unreadable", // file in uso
		0x80004005:               "unknown",
		0x800B0002:               "unknown", // TRUST_E_ACTION_UNKNOWN
	} {
		if got := statusOf(code); got != want {
			t.Errorf("statusOf(%#x) = %q, atteso %q", code, got, want)
		}
	}
	if !noSignature(trustENoSignature) || !noSignature(trustEProviderUnknown) || noSignature(0) || noSignature(trustEBadDigest) {
		t.Error("noSignature")
	}
	for lastErr, want := range map[uint32]string{
		0:                        "unsigned",
		trustENoSignature:        "unsigned",
		trustESubjectFormUnknown: "unsigned",
		trustEProviderUnknown:    "unsigned",
		5:                        "unreadable",
		0x80070020:               "unreadable",
		trustEBadDigest:          "invalid",
		87:                       "invalid",
	} {
		if got := unsignedStatus(lastErr); got != want {
			t.Errorf("unsignedStatus(%#x) = %q, atteso %q", lastErr, got, want)
		}
	}
	if codeHex(0) != "" || codeHex(trustENoSignature) != "0x800B0100" || codeHex(hresultWin32(5)) != "0x80070005" || hresultWin32(trustEBadDigest) != trustEBadDigest {
		t.Error("codici esadecimali")
	}
}

func TestPackagedApp(t *testing.T) {
	for p, want := range map[string]bool{
		`C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.21.3231.0_x64__8wekyb3d8bbwe\WindowsTerminal.exe`: true,
		`D:\WindowsApps\Gioco_1.0.0.0_x64__abc\gioco.exe`:                                                           true,
		`c:/program files/windowsapps/app/app.exe`:                                                                  true,
		`C:\Users\anna\AppData\Local\Microsoft\WindowsApps\winget.exe`:                                              false,
		`\\server\WindowsApps\app.exe`:                                                                              false,
		`C:\Program Files\App\app.exe`:                                                                              false,
		`C:\Temp\WindowsAppsFinte.exe`:                                                                              false,
	} {
		if packagedApp(p) != want {
			t.Errorf("packagedApp(%q) != %v", p, want)
		}
	}
}

func TestMicrosoftSigner(t *testing.T) {
	for name, want := range map[string]bool{
		"Microsoft Windows":           true,
		"Microsoft Windows Publisher": true,
		"Microsoft Corporation":       true,
		// Driver di altri produttori rifirmati da Microsoft: restano loro.
		"Microsoft Windows Hardware Compatibility Publisher":    false,
		"Microsoft Windows Third Party Component CA 2012":       false,
		"Microsoft Windows Early Launch Anti-malware Publisher": false,
		"microsoft windows":                    false,
		"Microsoft Corporation (contraffatto)": false,
		"":                                     false,
		"Google LLC":                           false,
	} {
		if microsoftSigner(name) != want {
			t.Errorf("microsoftSigner(%q) != %v", name, want)
		}
	}
}

func TestSysnative(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Windows\System32\svchost.exe`:       `C:\Windows\Sysnative\svchost.exe`,
		`c:\windows\system32\drivers\etc\hosts`: `c:\windows\Sysnative\drivers\etc\hosts`,
		`C:\WINDOWS\SYSTEM32`:                   `C:\WINDOWS\Sysnative`,
		`C:\Windows\SysWOW64\cmd.exe`:           `C:\Windows\SysWOW64\cmd.exe`,
		`C:\Windows\System32x\a.exe`:            `C:\Windows\System32x\a.exe`,
		`C:\Windows\explorer.exe`:               `C:\Windows\explorer.exe`,
		`D:\Windows\System32\a.exe`:             `D:\Windows\System32\a.exe`,
		`C:\Program Files\App\System32\a.exe`:   `C:\Program Files\App\System32\a.exe`,
		`İ C:\Windows\System32\a.exe`:           `İ C:\Windows\System32\a.exe`,
	} {
		if got := sysnative(in, `C:\Windows\`); got != want {
			t.Errorf("sysnative(%q) = %q, atteso %q", in, got, want)
		}
	}
	if sysnative(`C:\Windows\System32\a.exe`, "") != `C:\Windows\System32\a.exe` {
		t.Error("senza cartella di Windows")
	}
}

func TestTranslations(t *testing.T) {
	// Italiano Unicode (0410, 04B0) e inglese Windows-1252 (0409, 04E4).
	got := translations([]byte{0x10, 0x04, 0xB0, 0x04, 0x09, 0x04, 0xE4, 0x04, 0x01})
	if strings.Join(got, ",") != "041004B0,040904E4,040904B0" {
		t.Fatalf("traduzioni: %v", got)
	}
	if strings.Join(translations(nil), ",") != "040904B0,040904E4" {
		t.Fatalf("ripiego: %v", translations(nil))
	}
	if got := translations([]byte{0x09, 0x04, 0xB0, 0x04}); strings.Join(got, ",") != "040904B0,040904E4" {
		t.Fatalf("senza doppioni: %v", got)
	}
}

func TestCleanText(t *testing.T) {
	for in, want := range map[string]string{
		"  Microsoft\u00a0Corporation \x00":   "Microsoft Corporation",
		"Esplora\trisorse\r\n di Windows":     "Esplora risorse di Windows",
		"exe\u202Etxt.scr":                    "exetxt.scr",
		"a\u200Bb\uFEFF":                      "ab",
		"\ufffdNome":                          "Nome",
		"":                                    "",
		"10.0.26100.1 (WinBuild.160101.0800)": "10.0.26100.1 (WinBuild.160101.0800)",
	} {
		if got := cleanText(in); got != want {
			t.Errorf("cleanText(%q) = %q, atteso %q", in, got, want)
		}
	}
	long := strings.Repeat("àbc ", 60)
	got := []rune(cleanText(long))
	if len(got) > maxText || got[len(got)-1] != '…' {
		t.Fatalf("testo lungo: %d caratteri, %q", len(got), string(got))
	}
}

func TestFixedVersion(t *testing.T) {
	b := make([]byte, 52)
	copy(b, []byte{0xBD, 0x04, 0xEF, 0xFE})
	// 10.0 / 26100.2894
	copy(b[8:], []byte{0x00, 0x00, 0x0A, 0x00, 0x4E, 0x0B, 0xF4, 0x65})
	if v := fixedVersion(b); v != "10.0.26100.2894" {
		t.Fatalf("versione: %q", v)
	}
	if fixedVersion(b[:12]) != "" || fixedVersion(make([]byte, 52)) != "" {
		t.Fatal("struttura non valida")
	}
	b[0] = 0
	if fixedVersion(b) != "" {
		t.Fatal("firma della struttura")
	}
}

// Tempo scaduto: nessuna verifica e nessuna cache, così la lettura
// successiva verifica davvero; un file non leggibile non è «non firmato».
func TestFactsExpiredContextNotCached(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.exe")
	if err := os.WriteFile(p, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := New(dir, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := c.Facts(ctx, p)
	if f.Missing || f.Signature != nil || f.Folder == "" || len(c.cache) != 0 {
		t.Fatalf("contesto scaduto: %+v, cache %d", f, len(c.cache))
	}
	c.Facts(context.Background(), p)
	if len(c.cache) != 1 {
		t.Fatalf("cache dopo la verifica: %d", len(c.cache))
	}
}
