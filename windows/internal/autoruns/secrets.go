package autoruns

import (
	"regexp"
	"strings"
)

// Le righe di comando delle voci (Run, attività, servizi, consumatori WMI)
// sono le future righe di comando di un processo e possono contenere
// credenziali scritte per intero: «net use Z: \\nas\backup Passw0rd!
// /user:NAS\backup», «curl -u admin:segreta ...». Prima di esportarle si
// mascherano le forme note: la password diventa ‹password›, il nome
// dell'account ‹utente›. Il comando resta riconoscibile; file e target si
// calcolano dal testo originale, mai da questo.
var (
	// Credenziali in un indirizzo: schema://utente:password@host.
	urlCreds = regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s:@"]+:[^@\s/"]+@`)
	// Opzioni con la password come valore: -Password x, --password=x,
	// /pass:x, -pw x, -p x, /rp x (schtasks), --token x...
	passOption = regexp.MustCompile(`(?i)((?:^|\s)(?:--?password|/password|--?passwd|--?pass|/pass|--?pwd|/pwd|-pw|/pw|-p|/p|/rp|--?token|/token|--?api-?key|--?secret)(?::|=|\s+))("[^"]*"|[^\s"]+)`)
	// -u utente:password (curl e simili).
	userPass = regexp.MustCompile(`(?i)((?:^|\s)(?:-u|--user)\s+)("[^"]*"|[^\s"]+)`)
	// /user:NOME (net use, runas): il nome di un account.
	userOption = regexp.MustCompile(`(?i)((?:^|\s)/user:)("[^"]*"|[^\s"]+)`)
	// password=... in una stringa di connessione o in «sc config ... password= x».
	keyPass = regexp.MustCompile(`(?i)(\b(?:password|pwd)\s*=\s*)("[^"]*"|[^;\s"]+)`)
	// net use [unità:] \\server\condivisione password: la password segue la
	// condivisione, senza opzione.
	netUse = regexp.MustCompile(`(?i)(\bnet1?(?:\.exe)?"?\s+use\s+(?:[a-z]:\s+|\*\s+)?"?\\\\[^\s"]+"?\s+)("[^"]*"|[^\s/*"][^\s"]*)`)
)

// maskSecrets maschera le credenziali scritte in una riga di comando.
func maskSecrets(s string) string {
	s = urlCreds.ReplaceAllString(s, "${1}‹utente›:‹password›@")
	s = maskValue(passOption, s, func(v string) string {
		if v == "*" || isOption(v) {
			return "" // un'altra opzione o la richiesta della password
		}
		return "‹password›"
	})
	s = maskValue(userPass, s, func(v string) string {
		v = strings.Trim(v, `"`)
		if !strings.Contains(v, ":") || isAbs(v) || strings.Contains(v, "://") {
			return "" // -u senza «utente:password» è spesso altro (python -u x.py)
		}
		return "‹utente›:‹password›"
	})
	s = maskValue(userOption, s, func(string) string { return "‹utente›" })
	s = maskValue(keyPass, s, func(string) string { return "‹password›" })
	return maskValue(netUse, s, func(string) string { return "‹password›" })
}

// maskValue sostituisce il secondo gruppo di ogni corrispondenza di re con
// ciò che restituisce mask ("" lascia il valore com'è).
func maskValue(re *regexp.Regexp, s string, mask func(value string) string) string {
	idx := re.FindAllStringSubmatchIndex(s, -1)
	if idx == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range idx {
		vs, ve := m[4], m[5]
		if vs < 0 || vs < last {
			continue
		}
		r := mask(s[vs:ve])
		if r == "" || r == s[vs:ve] {
			continue
		}
		b.WriteString(s[last:vs])
		b.WriteString(r)
		last = ve
	}
	b.WriteString(s[last:])
	return b.String()
}
