package sign

import (
	"sync"
	"time"
)

// Durate dei contesti dei cataloghi tenuti aperti (catPool).
const (
	// catIdle: un contesto fermo da tanto si chiude; tra la verifica
	// dell'avvio automatico e quella dei processi della stessa analisi resta.
	catIdle = time.Minute
	// catMaxAge: un contesto non si riusa oltre questa età, così vede i
	// cataloghi installati nel frattempo (per esempio da Windows Update).
	catMaxAge = 5 * time.Minute
	// catKeep: contesti liberi tenuti per algoritmo, quante verifiche
	// insieme fanno i processi e l'avvio automatico.
	catKeep = 8
)

// catPool tiene aperti i contesti dei cataloghi di Windows
// (CryptCATAdminAcquireContext2), per algoritmo d'impronta, così non se ne
// apre e chiude uno per ogni file: a freddo l'avvio automatico verifica
// centinaia di file. Un contesto lo usa una sola goroutine alla volta
// (Microsoft non documenta l'uso dello stesso contesto da più thread
// insieme): get lo toglie dai liberi, put ce lo rimette. Quelli fermi da
// almeno idle, o aperti da almeno maxAge, si chiudono con release (sweep, a
// tempo): nessun contesto resta aperto senza uso. acquire restituisce il
// contesto (0 se non aperto) e il codice d'errore; su Windows sono le
// funzioni di wintrust.dll, nelle prove finte.
type catPool struct {
	acquire func(alg string) (uintptr, uint32)
	release func(uintptr)
	idle    time.Duration
	maxAge  time.Duration
	keep    int

	mu    sync.Mutex
	free  map[string][]*catCtx
	timer *time.Timer
}

// catCtx è un contesto aperto per un algoritmo.
type catCtx struct {
	alg    string
	h      uintptr
	opened time.Time
	used   time.Time
}

func newCatPool(acquire func(string) (uintptr, uint32), release func(uintptr)) *catPool {
	return &catPool{acquire: acquire, release: release, idle: catIdle, maxAge: catMaxAge, keep: catKeep, free: map[string][]*catCtx{}}
}

// get restituisce un contesto per l'algoritmo: uno libero se c'è, altrimenti
// uno nuovo. nil e il codice d'errore se non si apre.
func (p *catPool) get(alg string) (*catCtx, uint32) {
	t := now()
	var old []uintptr
	var c *catCtx
	p.mu.Lock()
	list := p.free[alg]
	for len(list) > 0 && c == nil {
		x := list[len(list)-1]
		list = list[:len(list)-1]
		if t.Sub(x.opened) < p.maxAge {
			c = x
		} else {
			old = append(old, x.h)
		}
	}
	p.free[alg] = list
	p.mu.Unlock()
	for _, h := range old {
		p.release(h)
	}
	if c != nil {
		return c, 0
	}
	h, fail := p.acquire(alg)
	if h == 0 {
		if fail == 0 {
			fail = trustEProviderUnknown
		}
		return nil, fail
	}
	return &catCtx{alg: alg, h: h, opened: t}, 0
}

// put rimette il contesto tra i liberi. keep falso lo chiude: dopo un
// errore il contesto potrebbe non essere più buono.
func (p *catPool) put(c *catCtx, keep bool) {
	if c == nil {
		return
	}
	t := now()
	p.mu.Lock()
	if !keep || t.Sub(c.opened) >= p.maxAge || len(p.free[c.alg]) >= p.keep {
		p.mu.Unlock()
		p.release(c.h)
		return
	}
	c.used = t
	p.free[c.alg] = append(p.free[c.alg], c)
	if p.timer == nil {
		p.timer = time.AfterFunc(p.idle, p.sweep)
	}
	p.mu.Unlock()
}

// sweep chiude i contesti liberi fermi da almeno idle o troppo vecchi; se
// ne restano, si riprogramma per la prima scadenza.
func (p *catPool) sweep() {
	t := now()
	var old []uintptr
	var next time.Duration
	p.mu.Lock()
	p.timer = nil
	for alg, list := range p.free {
		k := 0
		for _, c := range list {
			left := min(p.idle-t.Sub(c.used), p.maxAge-t.Sub(c.opened))
			if left <= 0 {
				old = append(old, c.h)
				continue
			}
			if next == 0 || left < next {
				next = left
			}
			list[k] = c
			k++
		}
		p.free[alg] = list[:k]
	}
	if next > 0 {
		p.timer = time.AfterFunc(next, p.sweep)
	}
	p.mu.Unlock()
	for _, h := range old {
		p.release(h)
	}
}
