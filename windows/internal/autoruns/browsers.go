package autoruns

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"lanterna/internal/scan"
)

// fileReader legge i file dei browser. Su Windows apre con la condivisione
// completa (lettura, scrittura e cancellazione) e chiude subito: Chrome
// salva le preferenze con ReplaceFile, che chiede l'accesso DELETE, e un
// file aperto senza FILE_SHARE_DELETE (come fa os.Open) lo farebbe fallire.
type fileReader struct {
	read func(path string) ([]byte, error)
	dirs func(path string) ([]string, error) // nomi delle sottocartelle
}

// chromiumBrowser è un browser basato su Chromium e la sua cartella User Data.
type chromiumBrowser struct {
	ID       string // chrome | edge | brave
	UserData string
}

// Percorsi degli store ufficiali nel campo update_url del manifest.
const (
	chromeStoreURL = "https://clients2.google.com/service/update2/crx"
	edgeStoreURL   = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
)

// chromiumExt è ciò che serve di una voce di extensions.settings.
type chromiumExt struct {
	Location       int             `json:"location"`
	DisableReasons json.RawMessage `json:"disable_reasons"`
	FromWebstore   bool            `json:"from_webstore"`
	ByDefault      bool            `json:"was_installed_by_default"`
	ByOEM          bool            `json:"was_installed_by_oem"`
	Path           string          `json:"path"`
	Manifest       *manifest       `json:"manifest"`
	Active         *struct {
		ExplicitHost   []string `json:"explicit_host"`
		ScriptableHost []string `json:"scriptable_host"`
	} `json:"active_permissions"`
}

// manifest è la parte del manifest.json che serve.
type manifest struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	DefaultLocale   string            `json:"default_locale"`
	UpdateURL       string            `json:"update_url"`
	Permissions     []json.RawMessage `json:"permissions"`
	HostPermissions []string          `json:"host_permissions"`
	ContentScripts  []struct {
		Matches []string `json:"matches"`
	} `json:"content_scripts"`
}

// prefsSettings decodifica di un file delle preferenze SOLO
// extensions.settings: account, e-mail e cronologia non si conservano.
func prefsSettings(b []byte) map[string]json.RawMessage {
	var p struct {
		Extensions struct {
			Settings map[string]json.RawMessage `json:"settings"`
		} `json:"extensions"`
	}
	if json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &p) != nil {
		return nil
	}
	return p.Extensions.Settings
}

// disabled: disable_reasons è un elenco di interi (assente o vuoto =
// attiva); i Chrome più vecchi lo scrivevano come un intero (0 = attiva).
func disabled(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var l []int
	if json.Unmarshal(raw, &l) == nil {
		for _, v := range l {
			if v != 0 {
				return true
			}
		}
		return false
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return n != 0
	}
	return false
}

// allSitesPatterns sono i permessi che danno accesso a tutti i siti.
var allSitesPatterns = map[string]bool{"<all_urls>": true, "*://*/*": true, "http://*/*": true, "https://*/*": true}

func anyAllSites(list ...[]string) bool {
	for _, l := range list {
		for _, p := range l {
			if allSitesPatterns[strings.TrimSpace(p)] {
				return true
			}
		}
	}
	return false
}

func (m *manifest) hosts() []string {
	if m == nil {
		return nil
	}
	out := append([]string(nil), m.HostPermissions...)
	for _, p := range m.Permissions {
		var s string
		if json.Unmarshal(p, &s) == nil {
			out = append(out, s)
		}
	}
	for _, c := range m.ContentScripts {
		out = append(out, c.Matches...)
	}
	return out
}

// chromiumSource traduce location (enum ManifestLocation di Chromium:
// 1 interna, 2 e 6 preferenze esterne, 3 registro, 4 decompressa, 5 e 10
// componenti, 7 e 9 criteri, 8 riga di comando) e gli indicatori di
// provenienza: store | policy | external | sideload | unpacked | component |
// default | other.
func chromiumSource(e chromiumExt, m *manifest, forced bool) string {
	switch e.Location {
	case 5, 10:
		return "component"
	case 7, 9:
		return "policy"
	}
	if forced {
		return "policy"
	}
	if e.ByDefault || e.ByOEM {
		return "default"
	}
	switch e.Location {
	case 1:
		if e.FromWebstore || m != nil && (m.UpdateURL == chromeStoreURL || m.UpdateURL == edgeStoreURL) {
			return "store"
		}
		return "other"
	case 2, 3, 6:
		return "external"
	case 4:
		return "unpacked"
	case 8:
		return "sideload"
	}
	return "other"
}

var msgRe = regexp.MustCompile(`^__MSG_([A-Za-z0-9_@]+)__$`)

// parseMessages legge un _locales/<lingua>/messages.json: chiave (senza
// badare alle maiuscole) → messaggio.
func parseMessages(b []byte) map[string]string {
	var m map[string]struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &m) != nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range m {
		out[strings.ToLower(k)] = v.Message
	}
	return out
}

// ResolveMessage risolve un nome «__MSG_chiave__» con i messaggi delle
// lingue indicate, in ordine (lingua dell'utente, la sola lingua,
// default_locale); restituisce name se non è un messaggio, "" se non si
// risolve.
func ResolveMessage(name string, locales []string, load func(locale string) map[string]string) string {
	m := msgRe.FindStringSubmatch(strings.TrimSpace(name))
	if m == nil {
		return name
	}
	key := strings.ToLower(m[1])
	for _, l := range locales {
		if l == "" {
			continue
		}
		if v := strings.TrimSpace(load(l)[key]); v != "" {
			return v
		}
	}
	return ""
}

// ChromiumLocales trasforma le lingue di Windows («it-IT») nelle cartelle
// _locales di Chromium («it_IT», poi «it»).
func ChromiumLocales(langs []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[strings.ToLower(s)] {
			seen[strings.ToLower(s)] = true
			out = append(out, s)
		}
	}
	for _, l := range langs {
		l = strings.ReplaceAll(strings.TrimSpace(l), "-", "_")
		add(l)
		if i := strings.IndexByte(l, '_'); i > 0 {
			add(l[:i])
		}
	}
	return out
}

// sortProfiles ordina le cartelle dei profili come le crea Chromium:
// «Default», poi «Profile 1», «Profile 2»... in ordine numerico, poi le altre.
func sortProfiles(names []string) []string {
	out := append([]string(nil), names...)
	rank := func(n string) (int, int) {
		if strings.EqualFold(n, "Default") {
			return 0, 0
		}
		if strings.HasPrefix(n, "Profile ") {
			if v, err := strconv.Atoi(strings.TrimPrefix(n, "Profile ")); err == nil {
				return 1, v
			}
		}
		return 2, 0
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, x := rank(out[i])
		b, y := rank(out[j])
		if a != b {
			return a < b
		}
		if x != y {
			return x < y
		}
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

// isAbsAny: percorso assoluto di Windows o del sistema su cui gira la prova.
func isAbsAny(p string) bool { return isAbs(p) || filepath.IsAbs(p) }

// highestVersion sceglie la cartella di versione più recente
// (Extensions\<id>\<versione>_0), confrontando i numeri.
func highestVersion(names []string) string {
	best := ""
	var bestParts []int
	for _, n := range names {
		parts := versionParts(n)
		if best == "" || lessParts(bestParts, parts) {
			best, bestParts = n, parts
		}
	}
	return best
}

func versionParts(s string) []int {
	var out []int
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == '.' || r == '_' }) {
		v, _ := strconv.Atoi(p)
		out = append(out, v)
	}
	return out
}

func lessParts(a, b []int) bool {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x < y
		}
	}
	return false
}

// chromiumItems legge le estensioni di tutti i profili di un browser
// Chromium: per ogni cartella con un file Preferences legge
// extensions.settings da Secure Preferences e da Preferences (su Windows
// fuori dominio è una preferenza protetta, in dominio no) e il manifest
// installato per il nome. Il profilo si esporta come numero, mai il nome
// della cartella. forced sono gli ID imposti dai criteri.
func (rd reader) chromiumItems(fs fileReader, b chromiumBrowser, locales []string, forced map[string]bool) []item {
	names, err := fs.dirs(b.UserData)
	if err != nil {
		return nil
	}
	// Preferences si legge una volta sola: dice che la cartella è un profilo
	// e poi serve per le estensioni.
	var profiles []string
	prefs := map[string][]byte{}
	for _, n := range names {
		if raw, err := fs.read(filepath.Join(b.UserData, n, "Preferences")); err == nil {
			profiles = append(profiles, n)
			prefs[n] = raw
		}
	}
	var out []item
	seenForced := map[string]bool{}
	for i, prof := range sortProfiles(profiles) {
		dir := filepath.Join(b.UserData, prof)
		settings := map[string]json.RawMessage{}
		for _, f := range []string{"Secure Preferences", "Preferences"} {
			var raw []byte
			var err error
			if f == "Preferences" {
				raw = prefs[prof]
				delete(prefs, prof)
			} else if raw, err = fs.read(filepath.Join(dir, f)); err != nil {
				continue
			}
			for id, v := range prefsSettings(raw) {
				if _, ok := settings[id]; !ok {
					settings[id] = v
				}
			}
		}
		ids := make([]string, 0, len(settings))
		for id := range settings {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			var e chromiumExt
			if json.Unmarshal(settings[id], &e) != nil {
				continue
			}
			if e.Location == 0 && e.Manifest == nil && e.Path == "" {
				continue // voce rimasta da un'estensione tolta
			}
			extDir := ""
			switch {
			case e.Path != "" && isAbsAny(e.Path):
				extDir = e.Path
			case e.Path != "":
				extDir = filepath.Join(dir, "Extensions", filepath.FromSlash(strings.ReplaceAll(e.Path, `\`, "/")))
			default:
				base := filepath.Join(dir, "Extensions", id)
				if vs, err := fs.dirs(base); err == nil && len(vs) > 0 {
					extDir = filepath.Join(base, highestVersion(vs))
				}
			}
			m := e.Manifest
			if extDir != "" {
				if raw, err := fs.read(filepath.Join(extDir, "manifest.json")); err == nil {
					var mm manifest
					if json.Unmarshal(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")), &mm) == nil {
						m = &mm
					}
				}
			}
			name, version := "", ""
			if m != nil {
				version = m.Version
				name = ResolveMessage(m.Name, append(append([]string(nil), locales...), m.DefaultLocale, "en"), func(l string) map[string]string {
					raw, err := fs.read(filepath.Join(extDir, "_locales", l, "messages.json"))
					if err != nil {
						return nil
					}
					return parseMessages(raw)
				})
			}
			src := chromiumSource(e, m, forced[strings.ToLower(id)])
			if forced[strings.ToLower(id)] {
				seenForced[strings.ToLower(id)] = true
			}
			var hosts []string
			if e.Active != nil {
				hosts = append(append(hosts, e.Active.ExplicitHost...), e.Active.ScriptableHost...)
			}
			it := rd.extensionItem(b.ID, i+1, id, name, version, src, !disabled(e.DisableReasons), anyAllSites(hosts, m.hosts()))
			if src == "unpacked" && e.Path != "" {
				it.entry.Command = rd.cl.path(e.Path)
			}
			out = append(out, it)
		}
	}
	// Estensioni imposte dai criteri ma non (ancora) installate in un profilo.
	var missing []string
	for id := range forced {
		if !seenForced[id] {
			missing = append(missing, id)
		}
	}
	sort.Strings(missing)
	for _, id := range missing {
		out = append(out, rd.extensionItem(b.ID, 0, id, "", "", "policy", true, false))
	}
	return out
}

func (rd reader) extensionItem(browser string, profile int, id, name, version, source string, enabled, allSites bool) item {
	if strings.TrimSpace(name) == "" {
		name = id
	}
	e := scan.AutorunEntry{Category: "browser", Kind: "extension", Name: rd.cl.text(strings.TrimSpace(name)), Browser: browser, ExtID: id,
		Version: version, Source: source, Profile: profile, Enabled: enabled, AllSites: allSites}
	return item{entry: e, component: source == "component"}
}

// ParseForcelist legge un valore di ExtensionInstallForcelist
// («id;update_url» o il solo id) e restituisce l'ID in minuscolo.
func ParseForcelist(v string) string {
	id, _, _ := strings.Cut(strings.TrimSpace(v), ";")
	return strings.ToLower(strings.TrimSpace(id))
}

// ffProfile è un profilo di profiles.ini.
type ffProfile struct {
	Path     string
	Relative bool
}

// parseProfilesIni legge le sezioni [ProfileN] di profiles.ini nell'ordine
// di N. Il nome (Name) è scelto dall'utente e non si legge.
func parseProfilesIni(b []byte) []ffProfile {
	type sec struct {
		n int
		p ffProfile
	}
	var secs []sec
	cur := -1
	for _, line := range strings.Split(string(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = -1
			name := line[1 : len(line)-1]
			if strings.HasPrefix(name, "Profile") {
				if n, err := strconv.Atoi(strings.TrimPrefix(name, "Profile")); err == nil {
					secs = append(secs, sec{n: n})
					cur = len(secs) - 1
				}
			}
			continue
		}
		if cur < 0 {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "Path":
			secs[cur].p.Path = strings.TrimSpace(v)
		case "IsRelative":
			secs[cur].p.Relative = strings.TrimSpace(v) == "1"
		}
	}
	sort.SliceStable(secs, func(i, j int) bool { return secs[i].n < secs[j].n })
	var out []ffProfile
	for _, s := range secs {
		if s.p.Path != "" {
			out = append(out, s.p)
		}
	}
	return out
}

// ffAddon è la parte di extensions.json di Firefox che serve.
type ffAddon struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	Version        string `json:"version"`
	Location       string `json:"location"`
	Active         bool   `json:"active"`
	UserDisabled   bool   `json:"userDisabled"`
	AppDisabled    bool   `json:"appDisabled"`
	ForeignInstall bool   `json:"foreignInstall"`
	SignedState    *int   `json:"signedState"`
	DefaultLocale  *struct {
		Name string `json:"name"`
	} `json:"defaultLocale"`
	UserPermissions *struct {
		Origins []string `json:"origins"`
	} `json:"userPermissions"`
}

func parseExtensionsJSON(b []byte) []ffAddon {
	var d struct {
		Addons []ffAddon `json:"addons"`
	}
	if json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &d) != nil {
		return nil
	}
	return d.Addons
}

// firefoxSource traduce la posizione di un componente aggiuntivo
// (XPIProvider): app-builtin e app-system-* sono di Firefox (componenti);
// winreg-*, app-global e app-system-share/local/user li ha messi un altro
// programma; nel profilo l'ha installato l'utente (store se firmato da
// Mozilla, signedState ≥ 2).
func firefoxSource(a ffAddon) string {
	switch l := strings.ToLower(a.Location); {
	case l == "app-builtin" || l == "app-builtin-addons" || l == "app-system-addons" || l == "app-system-defaults" || l == "app-system-profile":
		return "component"
	case l == "app-temporary":
		return "unpacked"
	case strings.HasPrefix(l, "winreg-") || l == "app-global" || l == "app-system-share" || l == "app-system-local" || l == "app-system-user":
		return "external"
	case l == "app-profile":
		switch {
		case a.ForeignInstall:
			return "external"
		case a.SignedState != nil && *a.SignedState >= 2:
			return "store"
		default:
			return "sideload"
		}
	}
	return "other"
}

// firefoxItems legge le estensioni di tutti i profili di Firefox da
// profiles.ini ed extensions.json. La cartella di un profilo contiene il
// nome scelto dall'utente: non si esporta mai, il profilo è un numero.
func (rd reader) firefoxItems(fs fileReader, root string) []item {
	raw, err := fs.read(filepath.Join(root, "profiles.ini"))
	if err != nil {
		return nil
	}
	var out []item
	for i, p := range parseProfilesIni(raw) {
		dir := filepath.FromSlash(strings.ReplaceAll(p.Path, `\`, "/"))
		if p.Relative || !isAbsAny(p.Path) {
			dir = filepath.Join(root, dir)
		} else {
			dir = p.Path
		}
		data, err := fs.read(filepath.Join(dir, "extensions.json"))
		if err != nil {
			continue
		}
		for _, a := range parseExtensionsJSON(data) {
			if a.Type != "extension" || a.ID == "" {
				continue
			}
			name := ""
			if a.DefaultLocale != nil {
				name = a.DefaultLocale.Name
			}
			var origins []string
			if a.UserPermissions != nil {
				origins = a.UserPermissions.Origins
			}
			out = append(out, rd.extensionItem("firefox", i+1, a.ID, name, a.Version, firefoxSource(a), a.Active, anyAllSites(origins)))
		}
	}
	return out
}
