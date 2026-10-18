//go:build !windows

package tools

import "errors"

// InstalledPrograms: il catalogo riguarda solo Windows.
func InstalledPrograms() map[string]Installed { return map[string]Installed{} }

// Open è disponibile solo su Windows.
func Open(id, target string) error {
	if _, err := Resolve(id, target, nil); err != nil && !errors.Is(err, ErrNotInstalled) {
		return err
	}
	return errors.New("gli strumenti si aprono solo sul PC Windows dove gira l'agente")
}
