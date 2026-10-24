// Package winps prepara l'avvio di Windows PowerShell (powershell.exe, la
// 5.1 presente in ogni Windows) per gli script in sola lettura dell'agente.
package winps

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

// Exe restituisce il percorso di powershell.exe nella cartella di sistema,
// così un programma con lo stesso nome altrove nel PATH non viene mai
// eseguito al suo posto.
func Exe(systemRoot string) string {
	if systemRoot == "" {
		return "powershell.exe"
	}
	return filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

// Env restituisce l'ambiente per powershell.exe senza PSModulePath, più le
// variabili extra. Se Polaris parte da PowerShell 7 eredita un PSModulePath
// con i moduli di PowerShell 7 in testa, e Windows PowerShell prova a
// caricare quelli: alcuni (come Microsoft.PowerShell.Security, dove sta
// Get-AuthenticodeSignature) sono fatti per .NET Core e non si caricano.
// Senza la variabile Windows PowerShell usa i propri percorsi predefiniti.
func Env(environ []string, extra ...string) []string {
	out := make([]string, 0, len(environ)+len(extra))
	for _, kv := range environ {
		if k, _, _ := strings.Cut(kv, "="); strings.EqualFold(k, "PSModulePath") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extra...)
}

// Explain aggiunge all'errore di uno script la prima riga che PowerShell ha
// scritto sullo standard error, se c'è (cmd.Output la conserva in
// exec.ExitError).
func Explain(err error) error {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return err
	}
	for _, line := range strings.Split(string(ee.Stderr), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			if r := []rune(line); len(r) > 200 {
				line = string(r[:200]) + "…"
			}
			return errors.New(err.Error() + ": " + line)
		}
	}
	return err
}
