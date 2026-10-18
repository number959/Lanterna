//go:build windows

package tools

import (
	"os"

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

// Open apre lo strumento indicato. Se Polaris gira come amministratore le
// pagine web si aprono tramite Esplora risorse, così il browser parte con i
// permessi normali dell'utente e non con quelli elevati.
func Open(id, target string) error {
	t, err := Resolve(id, target, InstalledPrograms())
	if err != nil {
		return err
	}
	file, args := t.File, t.Args
	if t.URL && windows.GetCurrentProcessToken().IsElevated() {
		file, args = "explorer.exe", `"`+t.File+`"`
	}
	verb, _ := windows.UTF16PtrFromString("open")
	f, err := windows.UTF16PtrFromString(file)
	if err != nil {
		return err
	}
	var a *uint16
	if args != "" {
		if a, err = windows.UTF16PtrFromString(args); err != nil {
			return err
		}
	}
	return windows.ShellExecute(0, verb, f, a, nil, windows.SW_SHOWNORMAL)
}
