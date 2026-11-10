package l2disc

import (
	"bytes"
	"encoding/hex"
	"net"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxRunes è la lunghezza massima di ogni testo esportato.
const maxRunes = 200

// clean decodifica un testo ricevuto dalla rete: UTF-8 con le sequenze non
// valide sostituite, caratteri di controllo e di formato (anche gli
// invisibili che cambiano la direzione del testo) trasformati in spazi,
// spazi ripetuti ridotti a uno, lunghezza limitata a maxRunes.
func clean(b []byte) string {
	var sb strings.Builder
	space := false
	for _, r := range strings.ToValidUTF8(string(b), "\uFFFD") {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			space = true
			continue
		}
		if space && sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		space = false
		sb.WriteRune(r)
	}
	return capRunes(sb.String())
}

// capRunes accorcia s a maxRunes caratteri, l'ultimo dei quali è "…".
func capRunes(s string) string {
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	r := []rune(s)
	return string(r[:maxRunes-1]) + "…"
}

// firstLine restituisce la prima riga non vuota di un testo su più righe
// (le descrizioni Cisco proseguono con supporto tecnico, copyright e data di
// compilazione).
func firstLine(b []byte) string {
	for _, line := range bytes.FieldsFunc(b, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if s := clean(line); s != "" {
			return s
		}
	}
	return ""
}

// printable dice se b è testo UTF-8 senza caratteri di controllo (gli zeri
// finali delle stringhe in stile C sono già stati tolti).
func printable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// idText esporta un identificativo che può essere testo o binario (nomi,
// alias, componenti, valori "locali", circuit ID): il testo pulito se è
// leggibile, senza numeri di serie (alcuni apparati usano il seriale come
// identificativo locale), altrimenti i byte in esadecimale.
func idText(b []byte) string {
	b = bytes.TrimRight(b, "\x00")
	if printable(b) {
		return stripSerials(clean(b))
	}
	return hexColon(b)
}

// hexColon scrive i byte come "01:02:ab", entro maxRunes caratteri.
func hexColon(b []byte) string {
	h := hex.EncodeToString(b)
	var sb strings.Builder
	for i := 0; i+2 <= len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return capRunes(sb.String())
}

// macString scrive un indirizzo MAC come aa:bb:cc:dd:ee:ff.
func macString(b []byte) string { return net.HardwareAddr(b).String() }

// Famiglie di indirizzi IANA usate da LLDP (Address Family Numbers).
const (
	afIPv4 = 1
	afIPv6 = 2
	af802  = 6 // indirizzo MAC
)

// ianaAddress decodifica "famiglia IANA + indirizzo"; ok è falso per le
// famiglie non gestite o le lunghezze sbagliate.
func ianaAddress(family byte, a []byte) (string, bool) {
	switch {
	case family == afIPv4 && len(a) == 4, family == afIPv6 && len(a) == 16:
		return net.IP(a).String(), true
	case family == af802 && len(a) == 6:
		return macString(a), true
	}
	return "", false
}

// appendUnique aggiunge s alla lista se non c'è già, entro max elementi.
func appendUnique(list []string, s string, max int) []string {
	if s == "" || len(list) >= max {
		return list
	}
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// Numeri di serie. Polaris non li esporta mai, ma alcuni apparati li mettono
// nei nomi: tra parentesi dopo il nome (i Nexus di Cisco annunciano
// "SW-CORE(FOC1234X5YZ)") oppure come nome predefinito (FortiSwitch e
// FortiGate usano il numero di serie, es. "S248DF3X17000123", finché
// l'amministratore non dà un nome). Le regole sono euristiche e prudenti: un
// nome che somiglia a un numero di serie viene tolto.
var (
	// Gruppo tra parentesi di sole maiuscole e cifre, con almeno due
	// lettere e due cifre (vedi parenSerialLike).
	parenSerial = regexp.MustCompile(`\s*\(\s*([0-9A-Z]{8,20})\s*\)`)
	// Etichetta esplicita seguita dal valore: "S/N: ABC123", "Serial Number ABC123".
	labelSerial = regexp.MustCompile(`(?i)\b(serial(?:[ _-]?(?:number|num|no\.?))?|s/n|sn)(\s*[:#=]\s*|\s+)([0-9a-z][0-9a-z-]{3,})`)
	// Nomi ricavati da un MAC (telefoni Cisco "SEP" + 12 cifre esadecimali).
	macDerived = regexp.MustCompile(`^[A-Z]{0,4}[0-9A-F]{12}$`)
)

func countDigitsLetters(s string) (digits, letters, run int) {
	cur := 0
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits++
			cur++
			run = max(run, cur)
		case unicode.IsLetter(r):
			letters++
			cur = 0
		default:
			cur = 0
		}
	}
	return digits, letters, run
}

func parenSerialLike(s string) bool {
	d, l, _ := countDigitsLetters(s)
	return d >= 2 && l >= 2
}

// serialLike dice se un nome intero sembra un numero di serie: 10-20
// maiuscole e cifre senza separatori, almeno due lettere e almeno cinque
// cifre di fila, e non ricavato da un MAC.
func serialLike(s string) bool {
	if len(s) < 10 || len(s) > 20 || macDerived.MatchString(s) {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9') && !(r >= 'A' && r <= 'Z') {
			return false
		}
	}
	_, l, run := countDigitsLetters(s)
	return l >= 2 && run >= 5
}

// redactLabeled sostituisce con "…" i valori preceduti da un'etichetta di
// numero di serie (purché contengano una cifra).
func redactLabeled(s string) string {
	return labelSerial.ReplaceAllStringFunc(s, func(m string) string {
		sub := labelSerial.FindStringSubmatch(m)
		if d, _, _ := countDigitsLetters(sub[3]); d == 0 {
			return m
		}
		return sub[1] + sub[2] + "…"
	})
}

// stripSerials toglie da un nome i numeri di serie riconoscibili.
func stripSerials(s string) string {
	s = parenSerial.ReplaceAllStringFunc(s, func(m string) string {
		if parenSerialLike(parenSerial.FindStringSubmatch(m)[1]) {
			return ""
		}
		return m
	})
	s = strings.TrimSpace(redactLabeled(s))
	if serialLike(s) {
		return ""
	}
	return s
}

// nameText pulisce un nome (di sistema, di dispositivo) e ne toglie i
// numeri di serie.
func nameText(b []byte) string { return stripSerials(clean(b)) }

// StripSerials toglie da un nome di apparato i numeri di serie riconoscibili
// (tra parentesi, o un nome che è un numero di serie, come il nome
// predefinito di molti firewall e switch). Lo usa anche la lettura SNMP.
func StripSerials(s string) string { return stripSerials(s) }

// descText pulisce una descrizione libera: prima riga, senza numeri di
// serie etichettati.
func descText(b []byte) string { return redactLabeled(firstLine(b)) }
