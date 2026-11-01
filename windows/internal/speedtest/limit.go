package speedtest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Limiti scelti da Polaris, ben sotto quelli di M-Lab (al massimo 40 test al
// giorno per chi li avvia a mano): un test ogni due minuti e dieci al giorno.
const (
	DefaultCooldown = 2 * time.Minute
	DefaultPerDay   = 10
)

// LimitFile: il file con lo stato dei limiti, nella cartella dei dati di
// Polaris. Contiene solo il giorno locale, il numero di test di quel giorno
// e l'ora dell'ultimo avvio: niente indirizzi, identificativi o server.
const LimitFile = "limiti-test-velocita.json"

// DefaultLimitPath: il file dei limiti nella cartella dei dati di Polaris
// (%LOCALAPPDATA%\STARNET Polaris su Windows, la cache dell'utente sugli
// altri sistemi), "" se la cartella non si trova (limiti solo in memoria).
func DefaultLimitPath() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, "STARNET Polaris", LimitFile)
}

// Limiter conta i test avviati, un test alla volta ogni Cooldown e al
// massimo PerDay nello stesso giorno (ora locale). Con Path lo stato sta in
// un file condiviso dall'agente e dalla riga di comando, che sopravvive ai
// riavvii; se il file non si legge o non si scrive i limiti restano in
// memoria e il test si può fare lo stesso. Due programmi che avviano un test
// nello stesso istante possono contarlo una volta sola: il file evita i
// test ripetuti, non è un lucchetto.
type Limiter struct {
	Cooldown time.Duration
	PerDay   int
	Now      func() time.Time
	// Path: file dello stato ("" = solo in memoria).
	Path string

	mu    sync.Mutex
	last  time.Time
	day   string
	count int
	// dirty: l'ultimo salvataggio non è riuscito, la memoria è più recente
	// del file.
	dirty bool
}

// NewLimiter restituisce il limitatore con i valori predefiniti, in memoria.
func NewLimiter() *Limiter {
	return &Limiter{Cooldown: DefaultCooldown, PerDay: DefaultPerDay, Now: time.Now}
}

// NewSharedLimiter restituisce il limitatore con i valori predefiniti e lo
// stato nel file condiviso (DefaultLimitPath).
func NewSharedLimiter() *Limiter {
	l := NewLimiter()
	l.Path = DefaultLimitPath()
	return l
}

// LimitError spiega perché un test non può partire e fra quanto riprovare.
type LimitError struct {
	Wait time.Duration
	msg  string
}

func (e *LimitError) Error() string { return e.msg }

func (l *Limiter) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// limitState è il contenuto del file: giorno locale, test di quel giorno,
// ora dell'ultimo avvio. Nient'altro.
type limitState struct {
	Day   string `json:"day"`
	Count int    `json:"count"`
	Last  string `json:"last,omitempty"`
}

// load legge lo stato dal file, che vale più della memoria perché lo
// aggiornano anche gli altri programmi. Se il file manca, non si legge o è
// rovinato resta la memoria; dopo un salvataggio non riuscito, del file si
// prendono solo i valori più alti.
func (l *Limiter) load() {
	if l.Path == "" {
		return
	}
	b, err := os.ReadFile(l.Path)
	if err != nil {
		return
	}
	var st limitState
	if json.Unmarshal(b, &st) != nil || st.Count < 0 {
		return
	}
	if _, err := time.Parse("2006-01-02", st.Day); err != nil {
		return
	}
	var last time.Time
	if st.Last != "" {
		if last, err = time.Parse(time.RFC3339Nano, st.Last); err != nil {
			return
		}
	}
	if !l.dirty {
		l.day, l.count, l.last = st.Day, st.Count, last
		return
	}
	switch {
	case st.Day > l.day:
		l.day, l.count = st.Day, st.Count
	case st.Day == l.day:
		l.count = max(l.count, st.Count)
	}
	if last.After(l.last) {
		l.last = last
	}
}

// save scrive lo stato in modo atomico (file temporaneo nella stessa
// cartella, poi rinominato): chi legge trova il file vecchio o quello nuovo,
// mai uno a metà.
func (l *Limiter) save() {
	if l.Path == "" {
		return
	}
	st := limitState{Day: l.day, Count: l.count}
	if !l.last.IsZero() {
		st.Last = l.last.Format(time.RFC3339Nano)
	}
	l.dirty = writeAtomic(l.Path, st) != nil
}

func writeAtomic(path string, st limitState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".limiti-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// recent: attesa prima del prossimo test, 0 se si può subito. Un ultimo
// avvio nel futuro (orologio spostato indietro) non blocca.
func (l *Limiter) recent(now time.Time) time.Duration {
	if l.last.IsZero() || l.last.After(now) || now.Sub(l.last) >= l.Cooldown {
		return 0
	}
	return l.Cooldown - now.Sub(l.last)
}

// Take registra l'avvio di un test, o spiega perché non può partire.
func (l *Limiter) Take() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	now := l.now()
	day := now.Format("2006-01-02")
	if day != l.day {
		l.day, l.count = day, 0
	}
	if l.PerDay > 0 && l.count >= l.PerDay {
		y, m, d := now.Date()
		tomorrow := time.Date(y, m, d+1, 0, 0, 0, 0, now.Location())
		return &LimitError{Wait: tomorrow.Sub(now), msg: fmt.Sprintf("oggi sono già stati fatti %d test di velocità, il massimo che Polaris consente per non pesare sui server di M-Lab: riprova domani", l.PerDay)}
	}
	if wait := l.recent(now); wait > 0 {
		return &LimitError{Wait: wait, msg: fmt.Sprintf("hai appena fatto un test di velocità: per non pesare sui server di M-Lab il prossimo si può avviare tra %s", waitText(wait))}
	}
	l.last = now
	l.count++
	l.save()
	return nil
}

// Release annulla l'ultimo Take: il test non ha raggiunto M-Lab (rete
// assente, proxy che rifiuta), quindi non conta.
func (l *Limiter) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	if l.count > 0 {
		l.count--
	}
	l.last = time.Time{}
	l.save()
}

// Status: attesa prima del prossimo test (0 = subito) e test ancora
// possibili oggi.
func (l *Limiter) Status() (wait time.Duration, left int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	now := l.now()
	count := l.count
	if now.Format("2006-01-02") != l.day {
		count = 0
	}
	left = max(0, l.PerDay-count)
	return l.recent(now), left
}

// waitText: "1 min 20 s", "45 s".
func waitText(d time.Duration) string {
	s := int((d + time.Second - 1) / time.Second)
	if s < 60 {
		return fmt.Sprintf("%d s", s)
	}
	if s%60 == 0 {
		return fmt.Sprintf("%d min", s/60)
	}
	return fmt.Sprintf("%d min %d s", s/60, s%60)
}
