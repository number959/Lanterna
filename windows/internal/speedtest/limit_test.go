package speedtest

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fileLimiter: un limitatore con lo stato nel file indicato e l'ora data.
func fileLimiter(path string, now *time.Time) *Limiter {
	l := NewLimiter()
	l.Path = path
	l.Now = func() time.Time { return *now }
	return l
}

// Il conteggio sta in un file condiviso dall'agente e dalla riga di comando:
// un riavvio dell'agente o un test da riga di comando non lo azzerano. Il
// file contiene solo il giorno, il numero di test e l'ora dell'ultimo avvio.
func TestLimiterSharedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "STARNET Polaris", LimitFile)
	now := time.Date(2026, 10, 31, 9, 0, 0, 0, time.Local)
	agent := fileLimiter(path, &now)
	if err := agent.Take(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("stato non salvato: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"count", "day", "last"}) || fields["day"] != "2026-10-31" || fields["count"] != 1.0 {
		t.Errorf("contenuto del file: %s", b)
	}
	// Riga di comando (o agente riavviato): un altro limitatore, stesso file.
	now = now.Add(30 * time.Second)
	cli := fileLimiter(path, &now)
	var le *LimitError
	if err := cli.Take(); !errors.As(err, &le) || le.Wait != 90*time.Second || !strings.Contains(err.Error(), "tra 1 min 30 s") {
		t.Fatalf("pausa di due minuti dopo il riavvio: %v", err)
	}
	if w, left := cli.Status(); w != 90*time.Second || left != 9 {
		t.Errorf("stato: %s %d", w, left)
	}
	// Un test che non ha raggiunto M-Lab non conta, neppure per gli altri.
	now = now.Add(2 * time.Minute)
	if err := cli.Take(); err != nil {
		t.Fatal(err)
	}
	cli.Release()
	if w, left := agent.Status(); w != 0 || left != 9 {
		t.Errorf("dopo Release: %s %d", w, left)
	}
	// Dieci al giorno, contati insieme.
	for i := 0; i < 9; i++ {
		l := []*Limiter{agent, cli}[i%2]
		if err := l.Take(); err != nil {
			t.Fatalf("test %d: %v", i+2, err)
		}
		now = now.Add(2 * time.Minute)
	}
	if err := fileLimiter(path, &now).Take(); err == nil || !strings.Contains(err.Error(), "oggi sono già stati fatti 10 test") {
		t.Fatalf("limite giornaliero: %v", err)
	}
	// Nessun file temporaneo lasciato nella cartella.
	if ents, _ := os.ReadDir(filepath.Dir(path)); len(ents) != 1 {
		t.Errorf("file nella cartella: %v", ents)
	}
}

// A mezzanotte il conteggio riparte, la pausa di due minuti no.
func TestLimiterDayRollover(t *testing.T) {
	path := filepath.Join(t.TempDir(), LimitFile)
	if err := os.WriteFile(path, []byte(`{"day":"2026-10-31","count":10,"last":"2026-10-31T23:59:30+01:00"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 31, 23, 59, 45, 0, time.FixedZone("CET", 3600))
	l := fileLimiter(path, &now)
	if err := l.Take(); err == nil || !strings.Contains(err.Error(), "riprova domani") {
		t.Fatalf("prima di mezzanotte: %v", err)
	}
	now = time.Date(2026, 11, 1, 0, 0, 30, 0, now.Location())
	if w, left := l.Status(); w != time.Minute || left != 10 {
		t.Errorf("dopo mezzanotte: %s %d", w, left)
	}
	now = now.Add(time.Minute)
	if err := l.Take(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"day":"2026-11-01","count":1,`) {
		t.Errorf("giorno nuovo: %s", b)
	}
}

// File rovinato, non leggibile o non scrivibile: si continua in memoria.
func TestLimiterBadFile(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 31, 9, 0, 0, 0, time.Local)
	for name, content := range map[string]string{
		"rovinato":          "{non è JSON",
		"conteggio assurdo": `{"day":"2026-10-31","count":-3}`,
		"giorno assurdo":    `{"day":"ieri","count":1}`,
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		l := fileLimiter(path, &now)
		if err := l.Take(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := l.Take(); err == nil {
			t.Fatalf("%s: secondo test subito accettato", name)
		}
		// Il file torna valido con lo stato giusto.
		if err := fileLimiter(path, &now).Take(); err == nil {
			t.Errorf("%s: il file non è stato riscritto", name)
		}
	}
	// Ultimo avvio nel futuro (orologio spostato indietro): non blocca per sempre.
	future := filepath.Join(dir, "futuro.json")
	_ = os.WriteFile(future, []byte(`{"day":"2026-10-31","count":1,"last":"2099-01-01T00:00:00Z"}`), 0o600)
	if err := fileLimiter(future, &now).Take(); err != nil {
		t.Errorf("ultimo avvio nel futuro: %v", err)
	}
	// La cartella è un file: niente salvataggio, il limite resta in memoria.
	block := filepath.Join(dir, "blocco")
	_ = os.WriteFile(block, nil, 0o600)
	l := fileLimiter(filepath.Join(block, LimitFile), &now)
	if err := l.Take(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := l.Take(); err == nil {
		t.Error("senza file il limite non vale più")
	}
	if w, left := l.Status(); w != time.Minute || left != 9 {
		t.Errorf("stato in memoria: %s %d", w, left)
	}
}

// Il file sta nella cartella dei dati di Polaris (%LOCALAPPDATA%\STARNET
// Polaris su Windows, la cache dell'utente altrove).
func TestDefaultLimitPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LocalAppData", dir)
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("HOME", dir)
	base, err := os.UserCacheDir()
	if err != nil {
		t.Skip(err)
	}
	if got, want := DefaultLimitPath(), filepath.Join(base, "STARNET Polaris", LimitFile); got != want {
		t.Errorf("%s, atteso %s", got, want)
	}
	if l := NewSharedLimiter(); l.Path != DefaultLimitPath() || l.Cooldown != DefaultCooldown || l.PerDay != DefaultPerDay {
		t.Errorf("limitatore condiviso: %+v", l)
	}
}
