package space

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// sanitizer toglie dai percorsi ciò che identifica le persone e il PC:
//   - il profilo di chi usa Polaris diventa %USERPROFILE%;
//   - i nomi dei profili in una cartella Users (anche in Windows.old, su
//     altre unità o nei backup) diventano ‹utente 1›, ‹utente 2›... in ordine
//     alfabetico, oppure %USERNAME% se sono quelli di chi usa Polaris;
//   - gli stessi nomi dentro i nomi di file e cartelle, come parole intere;
//   - gli indirizzi e-mail (Outlook chiama così i file .ost e .pst);
//   - i SID degli account nelle cartelle del Cestino, tenendo solo il numero
//     finale dell'account.
//
// Si lavora parte per parte del percorso e si confrontano i nomi senza
// badare alle maiuscole con strings.EqualFold, senza mai usare posizioni
// calcolate su strings.ToLower: alcune lettere (İ, Ⱥ) cambiano lunghezza in
// minuscolo.
type sanitizer struct {
	profile      string // percorso del profilo, senza "\" finale
	profilesBase string // nome della cartella dei profili, se non è "Users"
	self         []string
	others       map[string]string // nome in minuscolo -> ‹utente N›
	otherNames   []string          // nomi da cercare come parole, in ordine
}

// Nomi di profilo che non sono persone: restano come sono.
var genericProfiles = map[string]bool{"public": true, "default": true, "default user": true, "all users": true, "temp": true}

func genericProfile(name string) bool {
	l := strings.ToLower(name)
	return genericProfiles[l] || strings.HasPrefix(l, "temp.") || strings.HasPrefix(l, "defaultuser")
}

// Nomi troppo comuni per cercarli come parole dentro altri nomi ("User Data",
// "Visual Studio", "Temp"): come profilo si sostituiscono lo stesso.
var commonWords = map[string]bool{
	"user": true, "users": true, "utente": true, "utenti": true, "admin": true, "administrator": true, "amministratore": true,
	"guest": true, "ospite": true, "data": true, "studio": true, "ufficio": true, "office": true, "home": true, "pc": true,
	"owner": true, "proprietario": true, "test": true, "windows": true, "microsoft": true, "system": true, "local": true,
}

func wordMaskable(name string) bool {
	return utf8.RuneCountInString(name) >= 3 && !genericProfile(name) && !commonWords[strings.ToLower(name)]
}

// profileNames raccoglie i nomi delle cartelle che stanno in una cartella di
// profili dell'albero letto, così si nascondono anche quelli che in C:\Users
// non ci sono più (Windows.old, vecchie installazioni, backup).
func profileNames(root *node, profilesBase string) []string {
	var out []string
	var walk func(n *node)
	walk = func(n *node) {
		for _, c := range n.children {
			if isProfilesDir(n.name, profilesBase) {
				if parts := strings.Split(fullPath(c), `\`); len(parts) >= 2 && len(parts)-2 <= 3 {
					out = append(out, c.name)
				}
			}
			walk(c)
		}
	}
	walk(root)
	return out
}

func isProfilesDir(name, profilesBase string) bool {
	return strings.EqualFold(name, "Users") || strings.EqualFold(name, "Documents and Settings") || profilesBase != "" && strings.EqualFold(name, profilesBase)
}

func newSanitizer(env Env, found ...string) *sanitizer {
	z := &sanitizer{profile: strings.TrimSuffix(env.UserProfile, `\`), others: map[string]string{}}
	if b := baseName(env.ProfilesDir); b != "" && !strings.EqualFold(b, "Users") {
		z.profilesBase = b
	}
	// Chi usa Polaris: il nome utente e il nome della cartella del profilo.
	for _, s := range []string{env.Username, baseName(z.profile)} {
		if s != "" && !strings.HasSuffix(s, ":") && !genericProfile(s) {
			z.self = append(z.self, s)
		}
	}
	isSelf := func(s string) bool {
		for _, x := range z.self {
			if strings.EqualFold(x, s) {
				return true
			}
		}
		return false
	}
	names := append(append([]string(nil), env.OtherProfiles...), found...)
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	n := 0
	for _, name := range names {
		l := strings.ToLower(name)
		if _, dup := z.others[l]; dup || l == "" || genericProfile(name) || isSelf(name) {
			continue
		}
		n++
		z.others[l] = "‹utente " + itoa(n) + "›"
		if wordMaskable(name) {
			z.otherNames = append(z.otherNames, name)
		}
	}
	return z
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func (z *sanitizer) path(p string) string {
	parts := strings.Split(p, `\`)
	out := make([]string, 0, len(parts))
	for i, part := range parts {
		// Una cartella di profili vicina alla radice: X:\Users\nome,
		// X:\Windows.old\Users\nome, X:\Backup\PC\Users\nome.
		if i >= 2 && i-1 <= 3 && part != "" && isProfilesDir(parts[i-1], z.profilesBase) {
			if z.profile != "" && strings.EqualFold(strings.Join(parts[:i+1], `\`), z.profile) {
				out = append(out[:0], "%USERPROFILE%")
				continue
			}
			if !genericProfile(part) {
				out = append(out, z.profileAlias(part))
				continue
			}
		}
		out = append(out, z.part(part))
	}
	return strings.Join(out, `\`)
}

func (z *sanitizer) profileAlias(name string) string {
	for _, s := range z.self {
		if strings.EqualFold(s, name) {
			return "%USERNAME%"
		}
	}
	if a, found := z.others[strings.ToLower(name)]; found {
		return a
	}
	return "‹utente›"
}

var (
	sidRe   = regexp.MustCompile(`(?i)^S-1-5-21-\d+-\d+-\d+-(\d+)$`)
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`)
)

// part ripulisce il nome di un file o di una cartella.
func (z *sanitizer) part(s string) string {
	if m := sidRe.FindStringSubmatch(s); m != nil {
		return "S-1-5-21-…-" + m[1]
	}
	if strings.Contains(s, "@") {
		s = maskEmail(s)
	}
	for _, name := range z.self {
		if wordMaskable(name) {
			s = maskWord(s, name, "%USERNAME%")
		}
	}
	for _, name := range z.otherNames {
		s = maskWord(s, name, z.others[strings.ToLower(name)])
	}
	return s
}

// maskEmail sostituisce gli indirizzi e-mail tenendo l'estensione del file:
// "mario.rossi@studio.it.ost" diventa "‹e-mail›.ost".
func maskEmail(s string) string {
	if ext := extOf(s); ext != "" {
		stem := s[:len(s)-len(ext)]
		if emailRe.MatchString(stem) {
			return emailRe.ReplaceAllLiteralString(stem, "‹e-mail›") + s[len(stem):]
		}
	}
	return emailRe.ReplaceAllLiteralString(s, "‹e-mail›")
}

// maskWord sostituisce name in s quando è una parola a sé (non parte di una
// parola più lunga), senza badare alle maiuscole: "Mario_cv.docx" diventa
// "%USERNAME%_cv.docx", "Marion.txt" resta com'è.
func maskWord(s, name, with string) string {
	n := utf8.RuneCountInString(name)
	if n < 3 || len(s) == 0 {
		return s
	}
	wordRune := func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); {
		// Gli n caratteri che partono da i.
		j, k := i, 0
		for ; k < n && j < len(s); k++ {
			_, w := utf8.DecodeRuneInString(s[j:])
			j += w
		}
		if k == n && strings.EqualFold(s[i:j], name) {
			before, _ := utf8.DecodeLastRuneInString(s[:i])
			after, _ := utf8.DecodeRuneInString(s[j:])
			if (i == 0 || !wordRune(before)) && (j == len(s) || !wordRune(after)) {
				b.WriteString(s[last:i])
				b.WriteString(with)
				last, i = j, j
				continue
			}
		}
		_, w := utf8.DecodeRuneInString(s[i:])
		i += w
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}
