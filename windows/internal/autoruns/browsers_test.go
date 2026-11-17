package autoruns

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func osReader() fileReader {
	return fileReader{read: os.ReadFile, dirs: func(p string) ([]string, error) {
		des, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, d := range des {
			if d.IsDir() {
				out = append(out, d.Name())
			}
		}
		return out, nil
	}}
}

func TestBrowserHelpers(t *testing.T) {
	if !disabled(json.RawMessage(`[1, 8]`)) || disabled(json.RawMessage(`[]`)) || disabled(nil) || !disabled(json.RawMessage(`4`)) || disabled(json.RawMessage(`0`)) {
		t.Error("disable_reasons")
	}
	if got := sortProfiles([]string{"Profile 10", "Guest Profile", "Profile 2", "Default", "System Profile"}); !reflect.DeepEqual(got, []string{"Default", "Profile 2", "Profile 10", "Guest Profile", "System Profile"}) {
		t.Errorf("ordine dei profili: %q", got)
	}
	if got := ChromiumLocales([]string{"it-IT", "en-US", "it"}); !reflect.DeepEqual(got, []string{"it_IT", "it", "en_US", "en"}) {
		t.Errorf("lingue: %q", got)
	}
	if highestVersion([]string{"1.9.0_0", "1.10.0_0", "1.2_0"}) != "1.10.0_0" {
		t.Error("versione più recente")
	}
	msgs := map[string]map[string]string{"it": {"appname": "Nome italiano"}, "en": {"appname": "English name", "other": "x"}}
	load := func(l string) map[string]string { return msgs[l] }
	if ResolveMessage("__MSG_appName__", []string{"it_IT", "it", "en"}, load) != "Nome italiano" ||
		ResolveMessage("__MSG_other__", []string{"it", "en"}, load) != "x" ||
		ResolveMessage("__MSG_manca__", []string{"it"}, load) != "" ||
		ResolveMessage("Nome normale", nil, load) != "Nome normale" {
		t.Error("ResolveMessage")
	}
	if parseMessages([]byte("\xef\xbb\xbf{\"AppName\":{\"message\":\"Ciao\",\"description\":\"d\"}}"))["appname"] != "Ciao" {
		t.Error("messages.json con BOM")
	}
	if ParseForcelist(" ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP;https://clients2.google.com/service/update2/crx") != "abcdefghijklmnopabcdefghijklmnop" || ParseForcelist("idsolo") != "idsolo" {
		t.Error("ParseForcelist")
	}
	if !anyAllSites([]string{"https://*/*"}) || anyAllSites([]string{"https://example.com/*"}) {
		t.Error("anyAllSites")
	}
}

func TestChromiumExtensions(t *testing.T) {
	root := t.TempDir()
	ud := filepath.Join(root, "User Data")
	unpacked := filepath.Join(root, "dev", "mia")
	// Profilo Default: le preferenze protette in Secure Preferences; un
	// componente, un'estensione dello store, una disattivata, una
	// decompressa, una forzata dai criteri. Le preferenze contengono anche
	// dati personali che non devono uscire.
	writeFile(t, filepath.Join(ud, "Default", "Preferences"), `{"account_info":[{"email":"anna.rossi@example.com"}],"google":{"services":{"last_username":"anna.rossi@example.com"}},
	 "extensions":{"settings":{
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"location":1,"from_webstore":true,"path":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\2.0_0","active_permissions":{"explicit_host":["<all_urls>"]}},
	  "dddddddddddddddddddddddddddddddd":{"location":4,"path":`+jsonString(unpacked)+`}
	 }}}`)
	writeFile(t, filepath.Join(ud, "Default", "Secure Preferences"), `{"extensions":{"settings":{
	  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"location":5,"manifest":{"name":"Componente","version":"1"}},
	  "cccccccccccccccccccccccccccccccc":{"location":1,"from_webstore":true,"disable_reasons":[1],"manifest":{"name":"Disattivata","version":"3.1"}},
	  "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee":{"location":1,"manifest":{"name":"Forzata","version":"1"}},
	  "ffffffffffffffffffffffffffffffff":{"location":0}
	 }}}`)
	ext := filepath.Join(ud, "Default", "Extensions", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "2.0_0")
	writeFile(t, filepath.Join(ext, "manifest.json"), "\xef\xbb\xbf"+`{"name":"__MSG_appName__","version":"2.0","default_locale":"en","update_url":"https://clients2.google.com/service/update2/crx"}`)
	writeFile(t, filepath.Join(ext, "_locales", "it", "messages.json"), `{"appName":{"message":"Traduttore"}}`)
	writeFile(t, filepath.Join(ext, "_locales", "en", "messages.json"), `{"appName":{"message":"Translator"}}`)
	writeFile(t, filepath.Join(unpacked, "manifest.json"), `{"name":"Sviluppo","version":"0.1","host_permissions":["*://*/*"]}`)
	// Profilo 3: solo Preferences (PC in dominio), con il nome cartella scelto da Chromium.
	writeFile(t, filepath.Join(ud, "Profile 3", "Preferences"), `{"extensions":{"settings":{"gggggggggggggggggggggggggggggggg":{"location":2,"manifest":{"name":"Esterna","version":"5","content_scripts":[{"matches":["https://*/*"]}]}}}}}`)
	// Una cartella senza Preferences non è un profilo.
	writeFile(t, filepath.Join(ud, "Crashpad", "settings.dat"), "x")

	rd := testReader(newFakeEnv())
	// Ogni file Preferences (anche di vari MB) si legge una volta sola.
	fs := osReader()
	reads := map[string]int{}
	read := fs.read
	fs.read = func(p string) ([]byte, error) {
		reads[p]++
		return read(p)
	}
	items := rd.chromiumItems(fs, chromiumBrowser{ID: "chrome", UserData: ud}, []string{"it_IT", "it"}, map[string]bool{"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee": true, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz": true})
	for p, n := range reads {
		if n > 1 {
			t.Errorf("%s letto %d volte", p, n)
		}
	}
	got := map[string]item{}
	for _, it := range items {
		got[it.entry.ExtID] = it
	}
	if len(items) != 7 {
		t.Fatalf("voci: %d %+v", len(items), items)
	}
	check := func(id, name, source string, profile int, enabled, all, component bool) {
		t.Helper()
		it, ok := got[id]
		e := it.entry
		if !ok || e.Name != name || e.Source != source || e.Profile != profile || e.Enabled != enabled || e.AllSites != all || it.component != component || e.Browser != "chrome" || e.Category != "browser" {
			t.Errorf("%s: %+v (componente %v)", id, e, it.component)
		}
	}
	check("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "Traduttore", "store", 1, true, true, false)
	check("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "Componente", "component", 1, true, false, true)
	check("cccccccccccccccccccccccccccccccc", "Disattivata", "store", 1, false, false, false)
	check("dddddddddddddddddddddddddddddddd", "Sviluppo", "unpacked", 1, true, true, false)
	check("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "Forzata", "policy", 1, true, false, false)
	check("gggggggggggggggggggggggggggggggg", "Esterna", "external", 2, true, true, false)
	check("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "policy", 0, true, false, false)
	if got["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"].entry.Version != "2.0" || got["dddddddddddddddddddddddddddddddd"].entry.Command == "" {
		t.Errorf("versione o percorso della decompressa: %+v", got)
	}
	b, _ := json.Marshal(items[0].entry)
	all := string(b)
	for _, it := range items {
		b, _ := json.Marshal(it.entry)
		all += string(b)
	}
	for _, bad := range []string{"anna.rossi", "example.com", "Profile 3", "Default"} {
		if strings.Contains(all, bad) {
			t.Errorf("%q nelle voci esportate", bad)
		}
	}
	// Senza cartella User Data: nessuna voce, nessun errore.
	if rd.chromiumItems(osReader(), chromiumBrowser{ID: "edge", UserData: filepath.Join(root, "manca")}, nil, nil) != nil {
		t.Error("browser non installato")
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestFirefoxExtensions(t *testing.T) {
	root := t.TempDir()
	// La cartella del profilo contiene il nome scelto dall'utente.
	writeFile(t, filepath.Join(root, "profiles.ini"), "[General]\nStartWithLastProfile=1\n\n[Profile1]\nName=Lavoro di Anna\nIsRelative=1\nPath=Profiles/zz99yy88.Lavoro di Anna\n\n[Profile0]\nName=default\nIsRelative=1\nPath=Profiles/ab12cd34.default-release\nDefault=1\n\n[Install308046B0AF4A39CB]\nDefault=Profiles/ab12cd34.default-release\n")
	writeFile(t, filepath.Join(root, "Profiles", "ab12cd34.default-release", "extensions.json"), `{"schemaVersion":36,"addons":[
	 {"id":"uBlock0@raymondhill.net","type":"extension","version":"1.60.0","location":"app-profile","active":true,"signedState":2,"defaultLocale":{"name":"uBlock Origin"},"userPermissions":{"origins":["<all_urls>"],"permissions":["storage"]},"path":"C:\\Users\\anna\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\ab12cd34.default-release\\extensions\\uBlock0@raymondhill.net.xpi"},
	 {"id":"formautofill@mozilla.org","type":"extension","version":"1.0","location":"app-builtin","active":true,"defaultLocale":{"name":"Form Autofill"}},
	 {"id":"default-theme@mozilla.org","type":"theme","location":"app-builtin","active":true},
	 {"id":"helper@vendor.com","type":"extension","version":"3","location":"winreg-app-global","active":false,"userDisabled":true,"defaultLocale":{"name":"Vendor Helper"}},
	 {"id":"local@dev","type":"extension","version":"0.1","location":"app-profile","active":true,"signedState":0,"defaultLocale":{"name":"Locale"}}
	]}`)
	writeFile(t, filepath.Join(root, "Profiles", "zz99yy88.Lavoro di Anna", "extensions.json"), `{"addons":[{"id":"x@y","type":"extension","location":"app-profile","active":true,"foreignInstall":true,"signedState":2}]}`)
	rd := testReader(newFakeEnv())
	items := rd.firefoxItems(osReader(), root)
	if len(items) != 5 {
		t.Fatalf("voci: %+v", items)
	}
	want := []struct {
		id, name, source string
		profile          int
		enabled, all     bool
	}{
		{"uBlock0@raymondhill.net", "uBlock Origin", "store", 1, true, true},
		{"formautofill@mozilla.org", "Form Autofill", "component", 1, true, false},
		{"helper@vendor.com", "Vendor Helper", "external", 1, false, false},
		{"local@dev", "Locale", "sideload", 1, true, false},
		{"x@y", "x@y", "external", 2, true, false},
	}
	for i, w := range want {
		e := items[i].entry
		if e.ExtID != w.id || e.Name != w.name || e.Source != w.source || e.Profile != w.profile || e.Enabled != w.enabled || e.AllSites != w.all || e.Browser != "firefox" {
			t.Errorf("%d: %+v, atteso %+v", i, e, w)
		}
	}
	b, _ := json.Marshal([]any{items[0].entry, items[4].entry})
	for _, bad := range []string{"Anna", "anna", "ab12cd34", "Profiles"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("%q nelle voci: %s", bad, b)
		}
	}
	if got := parseProfilesIni([]byte("[Profile0]\nPath=C:\\Altrove\\p\nIsRelative=0\n")); len(got) != 1 || got[0].Relative || got[0].Path != `C:\Altrove\p` {
		t.Errorf("profilo assoluto: %+v", got)
	}
	if rd.firefoxItems(osReader(), filepath.Join(root, "manca")) != nil {
		t.Error("Firefox non installato")
	}
}
