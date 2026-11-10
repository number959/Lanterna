//go:build windows

package l2disc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/windows"

	"lanterna/internal/winps"
)

// Listen ascolta per la durata d (DefaultDuration se d <= 0, al massimo
// 5 minuti) gli annunci che arrivano alle schede cablate collegate e li
// riassume. Non trasmette nulla.
//
// Serve Polaris avviato come amministratore: altrimenti restituisce subito
// Read "admin" senza fare nulla. La cattura usa i comandi del modulo
// NetEventPacketCapture di Windows (nessun driver aggiuntivo):
//
//  1. si elencano le schede cablate collegate (nessuna: Read "nowired");
//  2. si chiudono le sessioni di Polaris rimaste da un avvio interrotto; se
//     esiste una sessione di cattura di altri ci si ferma (Windows ne
//     ammette una sola) senza toccarla;
//  3. si crea una sessione con nome unico ("Polaris-L2-<pid>") che salva
//     in un file .etl dentro una cartella temporanea nuova, con il filtro
//     sugli indirizzi di LLDP, CDP/DTP, STP e PVST+ e le schede cablate;
//  4. si ascolta per la durata richiesta, a intervalli di 250 ms;
//  5. si ferma la sessione, si leggono gli eventi 1001 del file e si
//     scrive una riga esadecimale per trama;
//  6. nel finally dello script si rimuovono sessione e file; se lo script è
//     stato interrotto (contesto annullato o scaduto) la sessione si chiude
//     da qui con un secondo script, poi si cancella la cartella.
func Listen(ctx context.Context, d time.Duration) Discovery {
	d = clampDuration(d)
	secs := int(d / time.Second)
	if !windows.GetCurrentProcessToken().IsElevated() {
		return Discovery{Read: ReadAdmin, Error: msgAdmin}
	}
	if ctx.Err() != nil {
		return Discovery{Read: ReadError, Error: msgCancelled}
	}
	tmp := os.TempDir()
	removeStale(tmp, time.Now())
	dir, err := os.MkdirTemp(tmp, tempPrefix)
	if err != nil {
		return Discovery{Read: ReadError, Error: msgNoTemp}
	}
	defer removeDir(dir)

	session := sessionPrefix + strconv.Itoa(os.Getpid())
	cctx, cancel := context.WithTimeout(ctx, d+setupTimeout)
	defer cancel()
	cmd := winps.Command(cctx, captureScript,
		"POLARIS_L2_SESSION="+session,
		"POLARIS_L2_ETL="+filepath.Join(dir, "cattura.etl"),
		"POLARIS_L2_SECONDS="+strconv.Itoa(secs))
	// Dopo l'interruzione non si aspetta oltre per lo standard output.
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.Output()
	c := parseCapture(string(out))
	if !c.clean {
		// Lo script non ha rimosso la sessione (interrotto, scaduto o
		// fallito durante la chiusura): la si chiude da qui.
		closeSession(session)
	}
	res := c.discovery(secs)
	if c.unfinished() {
		switch {
		case ctx.Err() != nil:
			res.Error = msgCancelled
		case cctx.Err() != nil:
			res.Error = msgTimeout
		case err != nil:
			res.Error = startError(err, dir, tmp)
		}
	}
	return res
}

// closeSession ferma e rimuove la sessione di cattura indicata, con un
// tempo massimo proprio: deve funzionare anche dopo l'annullamento del
// contesto dell'ascolto.
func closeSession(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	cmd := winps.Command(ctx, cleanupScript, "POLARIS_L2_SESSION="+name)
	cmd.WaitDelay = 5 * time.Second
	_ = cmd.Run()
}

// startError descrive un errore di PowerShell senza percorsi né nomi utente.
func startError(err error, dir, tmp string) string {
	var ee *exec.Error
	if errors.As(err, &ee) {
		return msgNoPS
	}
	return scrub("Cattura non avviata: "+winps.Explain(err).Error()+".",
		dir, tmp, os.Getenv("USERPROFILE"), os.Getenv("USERNAME"))
}
