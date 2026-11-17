package autoruns

import "lanterna/internal/pcinfo"

// cleaner è il pulitore comune (pcinfo.Cleaner) con i nomi brevi usati in
// questo pacchetto.
type cleaner struct {
	profile string // cartella del profilo di chi usa Polaris
	user    string // nome dell'account di chi usa Polaris
}

func (c cleaner) pc() pcinfo.Cleaner { return pcinfo.Cleaner{Profile: c.profile, User: c.user} }

// text pulisce un testo libero (nome di un'attività, di un consumatore WMI).
func (c cleaner) text(s string) string { return c.pc().Text(s) }

// path pulisce un percorso o una riga di comando.
func (c cleaner) path(s string) string { return c.pc().Path(s) }

// command pulisce una riga di comando da esportare: come path, e prima
// maschera le credenziali scritte per intero (maskSecrets), che il
// pulitore comune leggerebbe come un indirizzo e-mail (password@host).
func (c cleaner) command(s string) string { return c.path(maskSecrets(s)) }

// commonWords sono i nomi che non si mascherano (pcinfo.CommonWords).
var commonWords = pcinfo.CommonWords

func replaceWord(s, word, with string) string { return pcinfo.ReplaceWord(s, word, with) }
