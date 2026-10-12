// Package assets incorpora nell'eseguibile l'interfaccia web e il motore di
// analisi compilati da core/ (vedi scripts/build-windows.sh, che li copia in
// dist/ prima di "go build").
package assets

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// Web restituisce i file dell'interfaccia (index.html, assets/...).
func Web() fs.FS {
	sub, _ := fs.Sub(embedded, "dist")
	return sub
}

// Ready indica se la build ha incluso l'interfaccia.
func Ready() bool {
	_, err := fs.Stat(embedded, "dist/index.html")
	return err == nil
}
