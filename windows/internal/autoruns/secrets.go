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
	passOption = regexp.MustCompile(`(?i)((?:^|\s)(?:--?password|/password|--?passwd|--?pass|/pass|--?pwd|/pwd|-pw|/pw|-p|/p|/rp|--?token|/token|--?api-?key|--?secret)(?::|=|\s+))("[^"]*"|'[^']*'|[^\s"]+)`)
	// -u utente:password, --user=utente:password (curl e simili).
	userPass = regexp.MustCompile(`(?i)((?:^|\s)(?:-u|--user)(?:\s+|=))("[^"]*"|'[^']*'|[^\s"]+)`)
	// /user:NOME (net use, runas): il nome di un account.
	userOption = regexp.MustCompile(`(?i)((?:^|\s)/user:)("[^"]*"|[^\s"]+)`)
	// password=... in una stringa di connessione o in «sc config ... password= x».
	keyPass = regexp.MustCompile(`(?i)(\b(?:password|pwd)\s*=\s*)("[^"]*"|'[^']*'|[^;\s"]+)`)
	// PowerShell: ConvertTo-SecureString 'segreta' -AsPlainText.
	secureString = regexp.MustCompile(`(?i)(\bConvertTo-SecureString\s+(?:-String\s+)?)("[^"]*"|'[^']*'|[^\s"'();|]+)`)
	// La password attaccata all'opzione: 7-Zip e RAR (-pSegreta, -hpSegreta),
	// i client di MySQL e MariaDB (-pSegreta). Solo per questi programmi:
	// altrove «-p...» è spesso altro (-port, -print).
	attachedPassProg = regexp.MustCompile(`(?i)(?:^|[\s\\/"])(?:7z[agr]?|rar|winrar|unrar|mysql|mysqldump|mysqladmin|mysqlimport|mysqlcheck|mysqlpump|mariadb|mariadb-dump)(?:\.exe)?(?:"|\s|$)`)
	attachedPass     = regexp.MustCompile(`((?:^|\s)-h?p)("[^"]*"|[^\s"-][^\s"]*)`)
	// L'inizio di un comando net use: la password è un argomento senza
	// opzione dopo la condivisione (maskNetUse).
	netUseCmd = regexp.MustCompile(`(?i)\bnet1?(?:\.exe)?"?\s+use\b`)
	// Unità o dispositivo di net use (Z:, LPT1:, *).
	netDevice = regexp.MustCompile(`(?i)^(?:[a-z]:|(?:lpt|com)[0-9]:|\*)$`)
)

// maskSecrets maschera le credenziali scritte in una riga di comando.
func maskSecrets(s string) string {
	s = urlCreds.ReplaceAllString(s, "${1}‹utente›:‹password›@")
	s = maskValue(passOption, s, func(v string) string {
		if v == "*" || isOption(v) || strings.EqualFold(v, "yes") || strings.EqualFold(v, "no") {
			return "" // un'altra opzione, la richiesta della password, /p:yes di net use
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
	s = maskValue(secureString, s, func(v string) string {
		if strings.HasPrefix(v, "$") || isOption(v) {
			return "" // una variabile o un'altra opzione
		}
		return "‹password›"
	})
	if attachedPassProg.MatchString(s) {
		s = maskValue(attachedPass, s, func(string) string { return "‹password›" })
	}
	return maskNetUse(s)
}

// maskNetUse maschera la password di «net use [unità] \\server\condivisione
// password [/user:...]»: è il primo argomento senza «/» dopo la
// condivisione, anche dopo le opzioni (net use \\nas\x /user:nome
// password); «*» chiede la password e resta. Si ferma alla fine del comando
// (&, |, <, >, parentesi).
func maskNetUse(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range netUseCmd.FindAllStringIndex(s, -1) {
		if m[0] < last {
			continue
		}
		share := false
		for i := m[1]; i < len(s); {
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			start, quoted := i, false
			for i < len(s) && (quoted || s[i] != ' ' && s[i] != '\t') {
				if s[i] == '"' {
					quoted = !quoted
				} else if !quoted && strings.IndexByte("&|<>()", s[i]) >= 0 {
					break
				}
				i++
			}
			tok := s[start:i]
			if tok == "" {
				break // fine del testo o del comando
			}
			bare := strings.Trim(tok, `"`)
			switch {
			case strings.HasPrefix(bare, "/"):
				continue // un'opzione
			case !share && strings.HasPrefix(bare, `\\`):
				share = true
				continue
			case !share && netDevice.MatchString(bare):
				continue
			case share && bare != "*":
				b.WriteString(s[last:start])
				b.WriteString("‹password›")
				last = i
			}
			break
		}
	}
	b.WriteString(s[last:])
	return b.String()
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
