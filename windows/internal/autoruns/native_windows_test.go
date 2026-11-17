//go:build windows

package autoruns

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Prove su Windows reale (nella CI, da amministratore): le letture native
// restituiscono dati plausibili e nessun nome di account o cartella del
// profilo.

func nativeReader() reader {
	profile := os.Getenv("USERPROFILE")
	return reader{
		res: Resolver{Getenv: os.Getenv, Exists: func(p string) bool {
			st, err := os.Stat(p)
			return err == nil && !st.IsDir()
		}},
		cl: cleaner{profile: profile, user: os.Getenv("USERNAME")},
	}
}

// noPersonal controlla che nel JSON delle voci non ci siano il profilo
// dell'utente né il suo nome.
func noPersonal(t *testing.T, items []item) {
	t.Helper()
	var entries []any
	for _, it := range items {
		entries = append(entries, it.entry)
	}
	b, _ := json.Marshal(entries)
	low := strings.ToLower(string(b))
	if p := os.Getenv("USERPROFILE"); p != "" {
		if esc, _ := json.Marshal(strings.ToLower(p)); strings.Contains(low, strings.Trim(string(esc), `"`)) {
			t.Errorf("cartella del profilo nelle voci")
		}
	}
	for _, name := range []string{os.Getenv("USERNAME"), "runneradmin"} {
		if len(name) >= 3 && !commonWords[strings.ToLower(name)] && strings.Contains(low, strings.ToLower(name)) {
			t.Errorf("nome dell'account %q nelle voci", name)
		}
	}
}

func TestServicesWindows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := readServices(ctx, nativeReader())
	if r.err != nil {
		t.Fatalf("lettura: %v", r.err)
	}
	cats := map[string]int{}
	starts := map[string]int{}
	svchost, withFile := 0, 0
	for _, it := range r.items {
		e := it.entry
		cats[e.Category]++
		starts[e.Start]++
		switch e.Account {
		case "", "system", "localservice", "networkservice", "user", "other":
		default:
			t.Errorf("account non ridotto a categoria: %q", e.Account)
		}
		if strings.Contains(strings.ToLower(e.Command), "svchost") && !strings.EqualFold(baseOf(it.file), "svchost.exe") {
			svchost++
		}
		if it.file != "" {
			withFile++
		}
	}
	if len(r.items) < 50 || cats["services"] < 20 || cats["drivers"] < 20 || svchost < 10 || withFile < len(r.items)/2 {
		t.Errorf("servizi e driver: %d voci, categorie %v, svchost con ServiceDll %d, con file %d", len(r.items), cats, svchost, withFile)
	}
	noPersonal(t, r.items)
	t.Logf("%d voci, categorie %v, avvio %v, ServiceDll %d, negati %v", len(r.items), cats, starts, svchost, r.denied)
}

func TestRegistryWindows(t *testing.T) {
	r := readRegistry(context.Background(), nativeReader())
	if r.err != nil {
		t.Fatalf("lettura: %v", r.err)
	}
	kinds := map[string]int{}
	for _, it := range r.items {
		kinds[it.entry.Kind]++
		if it.entry.Kind == "bootexecute" && !it.hijack && !strings.EqualFold(baseOf(it.file), "autochk.exe") {
			t.Errorf("BootExecute predefinito senza autochk.exe: %+v", it)
		}
		if it.entry.Kind == "userinit" && !it.hijack && !strings.EqualFold(baseOf(it.file), "userinit.exe") {
			t.Errorf("Userinit: %+v", it)
		}
	}
	// Su ogni Windows ci sono BootExecute, Shell e Userinit di Winlogon,
	// pacchetti di autenticazione LSA (msv1_0) e monitor di stampa.
	for _, k := range []string{"bootexecute", "shell", "userinit", "lsa-auth", "printmon"} {
		if kinds[k] == 0 {
			t.Errorf("nessuna voce %q: %v", k, kinds)
		}
	}
	noPersonal(t, r.items)
	t.Logf("%d voci: %v", len(r.items), kinds)
}

func TestTasksWindows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := readTasks(ctx, nativeReader())
	if r.err != nil {
		t.Fatalf("lettura: %v", r.err)
	}
	if len(r.items) == 0 && len(r.denied) == 0 {
		t.Fatal("nessuna attività e nessun accesso negato")
	}
	triggers, withFile, runAs := map[string]int{}, 0, map[string]int{}
	for _, it := range r.items {
		e := it.entry
		for _, x := range e.Triggers {
			triggers[x]++
		}
		runAs[e.RunAs]++
		if it.file != "" {
			withFile++
		}
		if !strings.HasPrefix(e.Location, `\`) || e.LastResult == "" || !strings.HasPrefix(e.LastResult, "0x") {
			t.Errorf("attività: %+v", e)
		}
		if e.LastRun != "" {
			if _, err := time.Parse(time.RFC3339, e.LastRun); err != nil {
				t.Errorf("data non RFC 3339: %q", e.LastRun)
			}
		}
	}
	noPersonal(t, r.items)
	t.Logf("%d attività (con file %d), trigger %v, eseguite come %v, negati %v", len(r.items), withFile, triggers, runAs, r.denied)
}

func TestWMIWindows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := readWMI(ctx, nativeReader())
	if r.err != nil {
		t.Fatalf("lettura: %v", r.err)
	}
	noPersonal(t, r.items)
	for _, it := range r.items {
		t.Logf("%s %s collegato=%v %s", it.entry.Namespace, it.entry.Consumer, it.entry.Bound, it.entry.Name)
	}
}

func TestCollectWindows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	d, err := Collect(ctx)
	if d == nil {
		t.Fatalf("nessun dato: %v", err)
	}
	if err != nil {
		t.Logf("parti mancate: %v", err)
	}
	if d.Counts["services"].Total+d.Counts["drivers"].Total < 50 {
		t.Errorf("conteggi: %+v", d.Counts)
	}
	b, _ := json.Marshal(d)
	if p := os.Getenv("USERPROFILE"); p != "" {
		if esc, _ := json.Marshal(p); strings.Contains(strings.ToLower(string(b)), strings.ToLower(strings.Trim(string(esc), `"`))) {
			t.Error("cartella del profilo nel risultato")
		}
	}
	t.Logf("%d voci elencate; conteggi %+v; negati %v; parziale %v; amministratore %v", len(d.Entries), d.Counts, d.Denied, d.Partial, d.Elevated)
}
