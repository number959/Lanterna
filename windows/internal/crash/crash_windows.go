//go:build windows

package crash

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"lanterna/internal/scan"
)

const crashControl = `SYSTEM\CurrentControlSet\Control\CrashControl`

// Read legge impostazioni e file delle schermate blu di questo PC. Senza
// amministratore la cartella dei minidump di solito non è leggibile: il
// risultato lo dice (NeedsAdmin) e riporta comunque le impostazioni.
func Read(ctx context.Context) (*scan.CrashData, error) {
	return Collect(ctx, System{
		Settings: settings,
		ReadDir:  readDir,
		Stat:     stat,
		Open:     open,
	}), nil
}

// settings legge CrashControl in sola lettura. Se la chiave manca valgono i
// percorsi predefiniti di Windows.
func settings() (*scan.CrashSettings, string, string) {
	mdir, dfile := `%SystemRoot%\Minidump`, `%SystemRoot%\MEMORY.DMP`
	profile := os.Getenv("USERPROFILE")
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, crashControl, registry.QUERY_VALUE)
	if err != nil {
		return nil, expand(mdir), expand(dfile)
	}
	defer k.Close()
	s := &scan.CrashSettings{}
	if v, _, err := k.GetIntegerValue("CrashDumpEnabled"); err == nil && v <= 0xFF {
		n := int(v)
		s.DumpEnabled = &n
	}
	if v, _, err := k.GetIntegerValue("FilterPages"); err == nil && v == 1 {
		s.FilterPages = true
	}
	flag := func(name string) *bool {
		v, _, err := k.GetIntegerValue(name)
		if err != nil {
			return nil
		}
		b := v != 0
		return &b
	}
	s.AutoReboot, s.Overwrite, s.LogEvent = flag("AutoReboot"), flag("Overwrite"), flag("LogEvent")
	// GetStringValue non espande i REG_EXPAND_SZ: si mostra il valore com'è
	// scritto e si legge il percorso espanso.
	if v, _, err := k.GetStringValue("MinidumpDir"); err == nil && strings.TrimSpace(v) != "" {
		mdir = strings.TrimSpace(v)
	}
	if v, _, err := k.GetStringValue("DumpFile"); err == nil && strings.TrimSpace(v) != "" {
		dfile = strings.TrimSpace(v)
	}
	s.MinidumpDir, s.DumpFile = DisplayPath(mdir, profile), DisplayPath(dfile, profile)
	return s, expand(mdir), expand(dfile)
}

func expand(p string) string {
	if e, err := registry.ExpandString(p); err == nil && e != "" {
		return e
	}
	return p
}

// classify riporta gli errori di Windows a quelli che Collect riconosce.
func classify(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED), errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD):
		return fmt.Errorf("%w", fs.ErrPermission)
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return fmt.Errorf("%w", fs.ErrNotExist)
	}
	return err
}

func readDir(dir string) ([]Entry, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, classify(err)
	}
	out := make([]Entry, 0, len(des))
	for _, de := range des {
		fi, err := de.Info()
		if err != nil {
			continue
		}
		out = append(out, Entry{Name: de.Name(), Size: fi.Size(), Mod: fi.ModTime(), Dir: fi.IsDir()})
	}
	return out, nil
}

func stat(path string) (Entry, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Entry{}, classify(err)
	}
	return Entry{Name: fi.Name(), Size: fi.Size(), Mod: fi.ModTime(), Dir: fi.IsDir()}, nil
}

// open apre il file in sola lettura e condivisione completa: Windows o un
// altro programma possono scriverlo, rinominarlo o cancellarlo intanto.
func open(path string) (File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, classify(err)
	}
	return os.NewFile(uintptr(h), path), nil
}
