//go:build windows

package tools

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// uninstallEntries legge le voci di disinstallazione del computer (64 e 32
// bit) e dell'utente.
func uninstallEntries() []Entry {
	var out []Entry
	roots := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	for _, r := range roots {
		k, err := registry.OpenKey(r.root, r.path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		subs, _ := k.ReadSubKeyNames(0)
		for _, s := range subs {
			sk, err := registry.OpenKey(k, s, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			var e Entry
			e.Name, _, _ = sk.GetStringValue("DisplayName")
			e.Version, _, _ = sk.GetStringValue("DisplayVersion")
			e.Location, _, _ = sk.GetStringValue("InstallLocation")
			e.Icon, _, _ = sk.GetStringValue("DisplayIcon")
			sk.Close()
			if e.Name != "" {
				out = append(out, e)
			}
		}
		k.Close()
	}
	return out
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// InstalledPrograms rileva i programmi del catalogo già installati.
func InstalledPrograms() map[string]Installed {
	return Detect(uninstallEntries(), fileExists)
}

// Open apre lo strumento indicato: per i programmi, la copia inclusa in Polaris
// se c'è ed è integra, poi quella scaricata (con la firma verificata subito
// prima dell'avvio), infine quella installata. Se Polaris gira come
// amministratore le pagine web si aprono tramite Esplora risorse, così il
// browser parte con i permessi normali dell'utente e non con quelli elevati.
func Open(id, target string, f *Fetcher) error {
	bundled := BundledPrograms()
	var portable map[string]Downloaded
	if f != nil {
		portable = f.Find()
	}
	t, err := Resolve(id, target, Merge(Merge(InstalledPrograms(), PortableIncluded(portable)), bundled))
	if errors.Is(err, ErrNotInstalled) {
		switch {
		case bundled[id].Problem != "":
			return ErrModified
		case portable[id].Problem != "":
			return ErrDownloadModified
		}
	}
	if err != nil {
		return err
	}
	if d, ok := portable[id]; ok && d.Path != "" && t.File == d.Path {
		if err := f.Check(id, d.Path); err != nil {
			return err
		}
	}
	file, args := t.File, t.Args
	if t.URL && windows.GetCurrentProcessToken().IsElevated() {
		file, args = "explorer.exe", `"`+t.File+`"`
	}
	verb, _ := windows.UTF16PtrFromString("open")
	fp, err := windows.UTF16PtrFromString(file)
	if err != nil {
		return err
	}
	var a, dir *uint16
	if args != "" {
		if a, err = windows.UTF16PtrFromString(args); err != nil {
			return err
		}
	}
	if t.Dir != "" {
		if dir, err = windows.UTF16PtrFromString(t.Dir); err != nil {
			return err
		}
	}
	err = windows.ShellExecute(0, verb, fp, a, dir, windows.SW_SHOWNORMAL)
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return ErrCancelled
	}
	return err
}

const createNoWindow = 0x08000000

// signatureScript chiede a Windows la verifica Authenticode del file indicato
// in POLARIS_FILE: stato della firma, nome del firmatario e versione.
const signatureScript = `$ErrorActionPreference = 'Stop'
$p = $env:POLARIS_FILE
$s = Get-AuthenticodeSignature -LiteralPath $p
$cn = ''
if ($s.SignerCertificate) { $cn = $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }
$v = (Get-Item -LiteralPath $p).VersionInfo
[pscustomobject]@{ status = [string]$s.Status; signer = [string]$cn; version = [string]$v.ProductVersion; file = [string]$v.FileVersion } | ConvertTo-Json -Compress`

var defaultVerify = func(path string) (Signature, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", signatureScript)
	cmd.Env = append(os.Environ(), "POLARIS_FILE="+path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return Signature{}, err
	}
	return ParseSignature(out)
}
