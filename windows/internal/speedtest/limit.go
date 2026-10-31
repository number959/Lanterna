package speedtest

import (
	"fmt"
	"sync"
	"time"
)

// Limiti scelti da Polaris, ben sotto quelli di M-Lab (al massimo 40 test al
// giorno per chi li avvia a mano): un test ogni due minuti e dieci al giorno.
const (
	DefaultCooldown = 2 * time.Minute
	DefaultPerDay   = 10
)

// Limiter conta i test avviati dall'agente, in memoria: un test alla volta
// ogni Cooldown e al massimo PerDay nello stesso giorno (ora locale).
type Limiter struct {
	Cooldown time.Duration
	PerDay   int
	Now      func() time.Time

	mu    sync.Mutex
	last  time.Time
	day   string
	count int
}

// NewLimiter restituisce il limitatore con i valori predefiniti.
func NewLimiter() *Limiter {
	return &Limiter{Cooldown: DefaultCooldown, PerDay: DefaultPerDay, Now: time.Now}
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

// Take registra l'avvio di un test, o spiega perché non può partire.
func (l *Limiter) Take() error {
	l.mu.Lock()
	defer l.mu.Unlock()
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
	if !l.last.IsZero() && now.Sub(l.last) < l.Cooldown {
		wait := l.Cooldown - now.Sub(l.last)
		return &LimitError{Wait: wait, msg: fmt.Sprintf("hai appena fatto un test di velocità: per non pesare sui server di M-Lab il prossimo si può avviare tra %s", waitText(wait))}
	}
	l.last = now
	l.count++
	return nil
}

// Release annulla l'ultimo Take: il test non ha raggiunto M-Lab (rete
// assente, proxy che rifiuta), quindi non conta.
func (l *Limiter) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.count > 0 {
		l.count--
	}
	l.last = time.Time{}
}

// Status: attesa prima del prossimo test (0 = subito) e test ancora
// possibili oggi.
func (l *Limiter) Status() (wait time.Duration, left int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	count := l.count
	if now.Format("2006-01-02") != l.day {
		count = 0
	}
	left = max(0, l.PerDay-count)
	if !l.last.IsZero() && now.Sub(l.last) < l.Cooldown {
		wait = l.Cooldown - now.Sub(l.last)
	}
	return wait, left
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
