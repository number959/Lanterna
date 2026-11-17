//go:build windows

package autoruns

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
)

// readShared legge un file aprendolo con la condivisione completa
// (FILE_SHARE_READ|WRITE|DELETE) e lo chiude subito: mentre Polaris legge,
// il browser può continuare a salvare. os.Open non condivide DELETE e
// farebbe fallire ReplaceFile di Chrome. Un file in uso da un altro
// programma senza condivisione si riprova una volta.
func readShared(path string, max int64) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var h windows.Handle
	for try := 0; try < 2; try++ {
		h, err = windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil || !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("file troppo grande")
	}
	return b, nil
}

func subdirs(path string) ([]string, error) {
	des, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range des {
		if d.IsDir() {
			out = append(out, d.Name())
		}
	}
	return out, nil
}

// userLanguages sono le lingue dell'interfaccia di Windows dell'utente
// («it-IT»), per i nomi delle estensioni.
func userLanguages() []string {
	l, err := windows.GetUserPreferredUILanguages(windows.MUI_LANGUAGE_NAME)
	if err != nil {
		return nil
	}
	return l
}

// readBrowsers legge le estensioni di Chrome, Edge e Brave (cartelle User
// Data di %LOCALAPPDATA%) e di Firefox (%APPDATA%\Mozilla\Firefox), più i
// criteri ExtensionInstallForcelist di Chrome ed Edge.
func readBrowsers(ctx context.Context, rd reader) sourceResult {
	fs := fileReader{read: func(p string) ([]byte, error) { return readShared(p, 32<<20) }, dirs: subdirs}
	local, roaming := os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA")
	locales := ChromiumLocales(userLanguages())
	var res sourceResult
	if local != "" {
		for _, b := range []struct {
			chromiumBrowser
			policy string
		}{
			{chromiumBrowser{"chrome", filepath.Join(local, `Google\Chrome\User Data`)}, `SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`},
			{chromiumBrowser{"edge", filepath.Join(local, `Microsoft\Edge\User Data`)}, `SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist`},
			{chromiumBrowser{"brave", filepath.Join(local, `BraveSoftware\Brave-Browser\User Data`)}, ""},
		} {
			if ctx.Err() != nil {
				// Tempo scaduto: Collect lo dice già, in italiano (Partial).
				return res
			}
			forced := map[string]bool{}
			if b.policy != "" {
				forced = policyIDs(b.policy)
			}
			res.items = append(res.items, rd.chromiumItems(fs, b.chromiumBrowser, locales, forced)...)
		}
	}
	if roaming != "" {
		res.items = append(res.items, rd.firefoxItems(fs, filepath.Join(roaming, `Mozilla\Firefox`))...)
	}
	return res
}
