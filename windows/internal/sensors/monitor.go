package sensors

import (
	"context"
	"sync"
	"time"
)

// Source legge le fonti dei sensori: Windows in produzione, un sostituto nei
// test.
type Source interface {
	// Collect raccoglie un campione; i valori "di rapporto" (percentuali,
	// byte al secondo) richiedono due raccolte.
	Collect() error
	// Read restituisce i valori dell'ultima raccolta.
	Read() (Raw, error)
	Close()
}

// Monitor tiene aperte le fonti finché qualcuno legge i sensori e le chiude
// dopo un periodo di inattività. Più letture ravvicinate condividono lo
// stesso campione.
type Monitor struct {
	Open func() (Source, error)
	// Idle: dopo quanto senza letture si chiudono le fonti (60 s).
	Idle time.Duration
	// Min: intervallo minimo tra due raccolte (500 ms); sotto, si riusa
	// l'ultimo campione. Serve anche da attesa per la prima lettura.
	Min time.Duration
	Now func() time.Time
	// Sleep attende tra le prime due raccolte (sostituibile nei test).
	Sleep func(ctx context.Context, d time.Duration) error

	mu     sync.Mutex
	src    Source
	last   Snapshot
	lastAt time.Time
	used   time.Time
	timer  *time.Timer
}

func (m *Monitor) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Monitor) min() time.Duration {
	if m.Min > 0 {
		return m.Min
	}
	return 500 * time.Millisecond
}

func (m *Monitor) idle() time.Duration {
	if m.Idle > 0 {
		return m.Idle
	}
	return time.Minute
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Read restituisce lo stato attuale dei sensori.
func (m *Monitor) Read(ctx context.Context) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.used = now
	if m.src != nil && now.Sub(m.lastAt) < m.min() {
		return m.last, nil
	}
	if m.src == nil {
		if m.Open == nil {
			return Snapshot{}, ErrUnavailable
		}
		src, err := m.Open()
		if err != nil {
			return Snapshot{}, err
		}
		if err := src.Collect(); err != nil {
			src.Close()
			return Snapshot{}, err
		}
		sleep := m.Sleep
		if sleep == nil {
			sleep = sleepCtx
		}
		if err := sleep(ctx, m.min()); err != nil {
			src.Close()
			return Snapshot{}, err
		}
		m.src = src
	}
	if err := m.src.Collect(); err != nil {
		m.closeLocked()
		return Snapshot{}, err
	}
	raw, err := m.src.Read()
	if err != nil {
		m.closeLocked()
		return Snapshot{}, err
	}
	snap := Build(raw)
	snap.At = m.now()
	m.last, m.lastAt = snap, snap.At
	m.armLocked()
	return snap, nil
}

// armLocked programma la chiusura delle fonti dopo il periodo di inattività.
func (m *Monitor) armLocked() {
	if m.timer != nil {
		m.timer.Stop()
	}
	m.timer = time.AfterFunc(m.idle(), func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.src != nil && m.now().Sub(m.used) >= m.idle() {
			m.closeLocked()
		}
	})
}

func (m *Monitor) closeLocked() {
	if m.src != nil {
		m.src.Close()
		m.src = nil
	}
}

// Close chiude le fonti.
func (m *Monitor) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.timer != nil {
		m.timer.Stop()
	}
	m.closeLocked()
}
