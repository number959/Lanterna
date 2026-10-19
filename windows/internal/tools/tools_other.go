//go:build !windows

package tools

import "errors"

// InstalledPrograms: il catalogo riguarda solo Windows.
func InstalledPrograms() map[string]Installed { return map[string]Installed{} }

// La verifica della firma usa Windows: altrove non c'è.
var defaultVerify func(path string) (Signature, error)

// Open è disponibile solo su Windows.
func Open(id, target string, f *Fetcher) error {
	if _, err := Resolve(id, target, nil); err != nil && !errors.Is(err, ErrNotInstalled) {
		return err
	}
	return errors.New("gli strumenti si aprono solo sul PC Windows dove gira l'agente")
}
