package autoruns

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"lanterna/internal/pcinfo"
)

// cleaner toglie dai testi esportati ciò che identifica la persona, con le
// stesse regole del pacchetto space:
//   - le cartelle dei profili (pcinfo.SanitizeCommand): quella di chi usa
//     Polaris diventa %USERPROFILE%, le altre ‹utente›;
//   - i SID degli account (S-1-5-21-…), tenendo solo il numero finale, che
//     non identifica nessuno fuori dal PC: alcuni programmi li mettono nel
//     nome delle attività pianificate;
//   - gli indirizzi e-mail;
//   - il nome dell'utente come parola intera (per esempio nel nome di
//     un'attività creata da un programma).
type cleaner struct {
	profile string // cartella del profilo di chi usa Polaris
	user    string // nome dell'account di chi usa Polaris
}

var (
	sidRe  = regexp.MustCompile(`(?i)S-1-5-21-\d+-\d+-\d+-(\d+)`)
	mailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`)
)

// Nomi troppo comuni per cercarli come parole (gli stessi di space).
var commonWords = map[string]bool{
	"user": true, "users": true, "utente": true, "utenti": true, "admin": true, "administrator": true, "amministratore": true,
	"guest": true, "ospite": true, "data": true, "studio": true, "ufficio": true, "office": true, "home": true, "pc": true,
	"owner": true, "proprietario": true, "test": true, "windows": true, "microsoft": true, "system": true, "local": true,
	"public": true, "default": true,
}

// text pulisce un testo libero (nome di un'attività, di un consumatore WMI).
func (c cleaner) text(s string) string {
	s = sidRe.ReplaceAllString(s, "S-1-5-21-…-$1")
	s = mailRe.ReplaceAllString(s, "‹e-mail›")
	return replaceWord(s, c.user, "‹utente›")
}

// path pulisce un percorso o una riga di comando.
func (c cleaner) path(s string) string {
	return c.text(pcinfo.SanitizeCommand(s, c.profile))
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// replaceWord sostituisce word quando compare come parola intera, senza
// badare alle maiuscole: il confronto avviene sul testo originale con
// EqualFold, mai con posizioni calcolate su strings.ToLower.
func replaceWord(s, word, with string) string {
	word = strings.TrimSpace(word)
	if utf8.RuneCountInString(word) < 3 || commonWords[strings.ToLower(word)] {
		return s
	}
	var b strings.Builder
	i := 0
	for {
		j := pcinfo.IndexFold(s, word, i)
		if j < 0 {
			break
		}
		k := j + len(word)
		before, _ := utf8.DecodeLastRuneInString(s[:j])
		after, _ := utf8.DecodeRuneInString(s[k:])
		if (j == 0 || !isWordRune(before)) && (k == len(s) || !isWordRune(after)) {
			b.WriteString(s[i:j])
			b.WriteString(with)
		} else {
			b.WriteString(s[i:k])
		}
		i = k
	}
	b.WriteString(s[i:])
	return b.String()
}
