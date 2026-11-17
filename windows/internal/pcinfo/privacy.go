package pcinfo

import (
	"net/netip"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Cleaner toglie dai testi esportati ciò che identifica la persona. Lo usano
// i processi, l'avvio automatico e la cache comune delle firme, con le stesse
// regole del pacchetto space:
//   - le cartelle dei profili (SanitizeCommand): quella di chi usa Polaris
//     diventa %USERPROFILE%, le altre ‹utente›;
//   - i SID degli account locali e di dominio (S-1-5-21-…), tenendo solo il
//     numero finale, che non identifica nessuno fuori dal PC, e quelli degli
//     account Microsoft Entra ID (S-1-12-1-…), che sono per intero l'ID
//     dell'oggetto della persona: alcuni programmi li mettono nel nome delle
//     attività pianificate;
//   - gli indirizzi e-mail;
//   - gli indirizzi IP pubblici (‹indirizzo›); quelli privati, di loopback,
//     link-local e CGNAT restano, perché servono alla diagnosi;
//   - il nome dell'utente come parola intera (per esempio nel nome di
//     un'attività creata da un programma, o in un percorso di rete).
type Cleaner struct {
	Profile string // cartella del profilo di chi usa Polaris
	User    string // nome dell'account di chi usa Polaris
}

// DefaultCleaner è il Cleaner di chi usa Polaris (USERPROFILE e USERNAME).
func DefaultCleaner() Cleaner {
	return Cleaner{Profile: os.Getenv("USERPROFILE"), User: os.Getenv("USERNAME")}
}

var (
	sidRe = regexp.MustCompile(`(?i)S-1-5-21-\d+-\d+-\d+-(\d+)`)
	// Niente \b davanti: «GoogleUpdateTaskUserS-1-12-1-…Core» va riconosciuto.
	aadSidRe = regexp.MustCompile(`(?i)S-1-12-1-\d+-\d+-\d+-\d+`)
	mailRe   = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`)
	ipv4Re   = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	// Almeno due «:» di fila tra cifre esadecimali: gli indirizzi IPv6 e
	// anche gli orari (10:30:45), che netip.ParseAddr poi scarta.
	ipv6Re = regexp.MustCompile(`[0-9A-Fa-f]*(?::[0-9A-Fa-f]*){2,}`)
)

// CommonWords sono nomi troppo comuni per cercarli come parole (gli stessi
// di space): un account chiamato così non si maschera nei testi.
var CommonWords = map[string]bool{
	"user": true, "users": true, "utente": true, "utenti": true, "admin": true, "administrator": true, "amministratore": true,
	"guest": true, "ospite": true, "data": true, "studio": true, "ufficio": true, "office": true, "home": true, "pc": true,
	"owner": true, "proprietario": true, "test": true, "windows": true, "microsoft": true, "system": true, "local": true,
	"public": true, "default": true,
}

// Text pulisce un testo libero (nome di un'attività, di un consumatore WMI,
// di un processo).
func (c Cleaner) Text(s string) string {
	s = sidRe.ReplaceAllString(s, "S-1-5-21-…-$1")
	s = aadSidRe.ReplaceAllString(s, "S-1-12-1-…")
	s = mailRe.ReplaceAllString(s, "‹e-mail›")
	s = MaskPublicIPs(s)
	return ReplaceWord(s, c.User, "‹utente›")
}

// Path pulisce un percorso o una riga di comando.
func (c Cleaner) Path(s string) string {
	return c.Text(SanitizeCommand(s, c.Profile))
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// ReplaceWord sostituisce word quando compare come parola intera, senza
// badare alle maiuscole: il confronto avviene sul testo originale con
// EqualFold, mai con posizioni calcolate su strings.ToLower. Le parole di
// meno di tre lettere e quelle comuni (CommonWords) non si toccano.
func ReplaceWord(s, word, with string) string {
	word = strings.TrimSpace(word)
	if utf8.RuneCountInString(word) < 3 || CommonWords[strings.ToLower(word)] {
		return s
	}
	var b strings.Builder
	i := 0
	for {
		j := IndexFold(s, word, i)
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

// IndexFold è strings.Index senza distinguere maiuscole e minuscole, con le
// posizioni nel testo originale: cerca da from in poi e restituisce -1 se
// non trova sub.
func IndexFold(s, sub string, from int) int {
	if sub == "" {
		return -1
	}
	for j := from; j+len(sub) <= len(s); j++ {
		if strings.EqualFold(s[j:j+len(sub)], sub) {
			return j
		}
	}
	return -1
}

// publicProfiles sono le cartelle dei profili che non appartengono a una
// persona e restano nel testo.
var publicProfiles = map[string]bool{"public": true, "default": true, "default user": true, "all users": true, ".": true, "..": true}

func isSep(c byte) bool { return c == '\\' || c == '/' }

func isASCIILetter(c byte) bool { return (c|0x20) >= 'a' && (c|0x20) <= 'z' }

// nameStop dice se il carattere chiude di sicuro il nome della cartella di
// un profilo: i caratteri che Windows non ammette nel nome di un account
// (" / \ [ ] : ; | = , + * ? < >) e quelli di controllo (TAB, a capo).
func nameStop(c byte) bool {
	return c < 0x20 || c == 0x7f || strings.IndexByte(`"/\[]:;|=,+*?<>`, c) >= 0
}

// pathStart dice se il testo comincia con un altro percorso: un'unità
// (C:\ o C:/) o una condivisione (\\server).
func pathStart(s string) bool {
	return (len(s) >= 3 && isASCIILetter(s[0]) && s[1] == ':' && isSep(s[2])) || strings.HasPrefix(s, `\\`)
}

// nameEnd restituisce la fine del nome della cartella del profilo che
// comincia in s[k:]. Il nome finisce a un carattere di nameStop, a uno
// spazio seguito da un altro percorso (robocopy C:\Users\a C:\Users\b) e a
// un apostrofo non seguito da una lettera: 'C:\Users\luca' si chiude,
// «Marco D'Amico» e «Lucia Dell'Acqua» restano interi.
func nameEnd(s string, k int) int {
	for e := k; e < len(s); e++ {
		switch c := s[e]; {
		case nameStop(c):
			return e
		case c == '\'':
			r, _ := utf8.DecodeRuneInString(s[e+1:])
			if e+1 == len(s) || !unicode.IsLetter(r) {
				return e
			}
		case c == ' ' && pathStart(s[e+1:]):
			return e
		}
	}
	return len(s)
}

// matchFold confronta s, da i in poi, con pat senza badare alle maiuscole
// (lettera per lettera con EqualFold, mai con posizioni calcolate su
// strings.ToLower) e con «\» e «/» equivalenti, una serie di barre come una
// sola (C:\\Users\\luca, C:/Users/luca). Restituisce la fine del tratto.
func matchFold(s string, i int, pat string) (int, bool) {
	for j := 0; j < len(pat); {
		if isSep(pat[j]) {
			if i >= len(s) || !isSep(s[i]) {
				return 0, false
			}
			for i < len(s) && isSep(s[i]) {
				i++
			}
			for j < len(pat) && isSep(pat[j]) {
				j++
			}
			continue
		}
		if i >= len(s) {
			return 0, false
		}
		pr, pn := utf8.DecodeRuneInString(pat[j:])
		sr, sn := utf8.DecodeRuneInString(s[i:])
		if pr != sr && !strings.EqualFold(pat[j:j+pn], s[i:i+sn]) {
			return 0, false
		}
		i, j = i+sn, j+pn
	}
	return i, true
}

// afterSeps restituisce la posizione dopo le barre che cominciano in s[i]
// (almeno una), oppure false.
func afterSeps(s string, i int) (int, bool) {
	if i >= len(s) || !isSep(s[i]) {
		return 0, false
	}
	for i < len(s) && isSep(s[i]) {
		i++
	}
	return i, true
}

func hasSuffixFold(s, suffix string) bool {
	return len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix)
}

// driveRoot dice se il testo finisce con la radice di un'unità: «C:»,
// «%SystemDrive%», «%HOMEDRIVE%», la condivisione amministrativa
// «\\server\C$», «…\Windows.old», la copia della versione precedente di
// Windows, oppure un volume indicato con il nome del dispositivo.
func driveRoot(t string) bool {
	n := len(t)
	switch {
	case n >= 2 && t[n-1] == ':' && isASCIILetter(t[n-2]):
		if n == 2 {
			return true
		}
		r, _ := utf8.DecodeLastRuneInString(t[:n-2])
		return !isWordRune(r) && r != '_'
	case n >= 3 && t[n-1] == '$' && isASCIILetter(t[n-2]) && isSep(t[n-3]):
		return true
	case hasSuffixFold(t, "%systemdrive%"), hasSuffixFold(t, "%homedrive%"):
		return true
	case hasSuffixFold(t, "windows.old"):
		return n > len("windows.old") && isSep(t[n-len("windows.old")-1])
	}
	// Il volume con il nome del dispositivo (\Device\HarddiskVolume3) e le
	// copie shadow (\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1).
	d := strings.TrimRight(t, "0123456789")
	return len(d) < n && (hasSuffixFold(d, `\device\harddiskvolume`) || hasSuffixFold(d, `\device\harddiskvolumeshadowcopy`))
}

// profilesAt riconosce in s[j:], dove s[j] è una barra, la cartella dei
// profili di Windows alla radice di un'unità (driveRoot): «\Users\» o
// «\Documents and Settings\». Restituisce l'inizio del nome dell'utente.
// Una cartella «Users» più in profondità (C:\App\Users\x) non conta.
func profilesAt(s string, j int) (int, bool) {
	if !driveRoot(s[:j]) {
		return 0, false
	}
	i, _ := afterSeps(s, j)
	for _, d := range []string{"users", "documents and settings"} {
		if k, ok := matchFold(s, i, d); ok {
			if k, ok := afterSeps(s, k); ok {
				return k, true
			}
		}
	}
	return 0, false
}

// SanitizeCommand toglie dai comandi e dai percorsi le cartelle degli
// utenti. Quella di chi usa Polaris (profile) diventa %USERPROFILE%; quelle
// degli altri utenti diventano ‹utente›, sia nella stessa cartella radice
// del profilo (di solito C:\Users) sia nella cartella dei profili di
// qualsiasi unità (D:\Users, C:\Windows.old\Users, %SystemDrive%\Users,
// \\server\C$\Users, C:\Documents and Settings). «\» e «/» valgono uguali.
// Il nome si confronta per intero ("anna" non è "annabella") e finisce dove
// dice nameEnd.
func SanitizeCommand(cmd, profile string) string {
	cmd = strings.TrimSpace(cmd)
	profile = strings.TrimRight(strings.TrimSpace(profile), `\/`)
	root, own := "", ""
	if sep := strings.LastIndexAny(profile, `\/`); sep > 0 {
		root, own = profile[:sep], profile[sep+1:]
	}
	// Gli altri utenti sotto la radice del profilo solo con una radice vera
	// (C:\Users, E:\Profili), mai con "C:".
	others := strings.ContainsAny(root, `\/`)
	var b strings.Builder
	i := 0 // il testo prima di i è già scritto
	for j := 0; j < len(cmd); {
		// La radice del profilo di chi usa Polaris.
		if root != "" {
			if e, ok := matchFold(cmd, j, root); ok {
				if k, ok := afterSeps(cmd, e); ok {
					e := nameEnd(cmd, k)
					for e > k && cmd[e-1] == ' ' {
						e--
					}
					name := cmd[k:e]
					switch {
					case own != "" && strings.EqualFold(name, own):
						b.WriteString(cmd[i:j])
						b.WriteString("%USERPROFILE%")
						i, j = e, e
						continue
					case others && maskable(name):
						b.WriteString(cmd[i:k])
						b.WriteString("‹utente›")
						i, j = e, e
						continue
					case others:
						j = e
						continue
					}
					// Radice "C:": la stessa posizione può essere C:\Users.
				}
			}
		}
		// La cartella dei profili di un'unità qualsiasi.
		if isSep(cmd[j]) {
			if k, ok := profilesAt(cmd, j); ok {
				e := nameEnd(cmd, k)
				for e > k && cmd[e-1] == ' ' {
					e--
				}
				if maskable(cmd[k:e]) {
					b.WriteString(cmd[i:k])
					b.WriteString("‹utente›")
					i = e
				}
				j = max(e, j+1)
				continue
			}
		}
		j++
	}
	b.WriteString(cmd[i:])
	return b.String()
}

// maskable dice se il nome della cartella di un profilo è di una persona:
// non vuoto, non una cartella comune (Public, Default), non una variabile
// (%USERNAME%).
func maskable(name string) bool {
	return name != "" && !publicProfiles[strings.ToLower(name)] && !strings.HasPrefix(name, "%")
}

// cgnat è lo spazio condiviso dei gestori (RFC 6598), non instradato su
// Internet.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicIP dice se l'indirizzo è pubblico, cioè un dato personale: non
// privato (RFC 1918, fc00::/7), di loopback, link-local, CGNAT, multicast o
// di «questa rete» (0.0.0.0/8).
func publicIP(a netip.Addr) bool {
	a = a.Unmap()
	if a.Is4() && a.As4()[0] == 0 {
		return false
	}
	return a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

// Caratteri che staccano un indirizzo dal resto del testo (MaskPublicIPs):
// spazi e a capo, la punteggiatura dei comandi e gli operatori della riga
// di comando (ping 203.0.113.5>nul, ping 203.0.113.5|find, a&b).
const (
	ipBefore = " \t\r\n:/@=\"'([{,;<>|&"
	ipAfter  = " \t\r\n:/\"')]},;<>|&?#%"
)

// shareHost dice se l'indirizzo che comincia in s[a] è il server di una
// condivisione: \\host all'inizio di un percorso (non una barra raddoppiata
// dentro un percorso, come C:\\App\\1.2.3.4\\x.exe), oppure \\?\UNC\host e
// \Device\Mup\host.
func shareHost(s string, a int) bool {
	if a >= 2 && s[a-2:a] == `\\` && (a == 2 || strings.IndexByte(ipBefore, s[a-3]) >= 0) {
		return true
	}
	return hasSuffixFold(s[:a], `\unc\`) || hasSuffixFold(s[:a], `\mup\`)
}

// ipEnd dice se l'indirizzo finito in s[b] è staccato da ciò che segue: fine
// del testo, un carattere di ipAfter, un punto che chiude la frase, oppure,
// dopo il server di una condivisione, «\» e «@» (\\host@SSL\DavWWWRoot).
func ipEnd(s string, b int, share bool) bool {
	switch {
	case b == len(s) || strings.IndexByte(ipAfter, s[b]) >= 0:
		return true
	case s[b] == '.':
		return b+1 == len(s) || strings.IndexByte(" \t\r\n\"')", s[b+1]) >= 0
	}
	return share && (s[b] == '\\' || s[b] == '@')
}

// MaskPublicIPs sostituisce con ‹indirizzo› gli indirizzi IP pubblici di un
// comando o di un testo (mstsc /v:203.0.113.5, admin@203.0.113.5,
// sftp://198.51.100.20/backup, \\203.0.113.5\dati). Un indirizzo conta solo
// se staccato dal resto: prima inizio o un carattere di ipBefore, oppure è
// il server di una condivisione (shareHost); dopo, ipEnd. Così non si
// toccano le versioni nei percorsi (EdgeUpdate\1.3.195.39\) né nei nomi dei
// file (setup-8.8.8.8.exe).
func MaskPublicIPs(s string) string {
	if !strings.ContainsAny(s, ".:") {
		return s
	}
	type span struct{ a, b int }
	var spans []span
	for _, re := range []*regexp.Regexp{ipv4Re, ipv6Re} {
		for _, m := range re.FindAllStringIndex(s, -1) {
			a, b := m[0], m[1]
			share := shareHost(s, a)
			if !share && a > 0 && strings.IndexByte(ipBefore, s[a-1]) < 0 {
				continue
			}
			if !ipEnd(s, b, share) {
				continue
			}
			if ip, err := netip.ParseAddr(s[a:b]); err == nil && publicIP(ip) {
				spans = append(spans, span{a, b})
			}
		}
	}
	if len(spans) == 0 {
		return s
	}
	// I tratti delle due espressioni non si sovrappongono (in un IPv6 come
	// ::ffff:203.0.113.5 si maschera la parte IPv4): si scrivono in ordine.
	var b strings.Builder
	i := 0
	for len(spans) > 0 {
		k := 0
		for x := range spans {
			if spans[x].a < spans[k].a {
				k = x
			}
		}
		sp := spans[k]
		spans = append(spans[:k], spans[k+1:]...)
		if sp.a < i {
			continue
		}
		b.WriteString(s[i:sp.a])
		b.WriteString("‹indirizzo›")
		i = sp.b
	}
	b.WriteString(s[i:])
	return b.String()
}
