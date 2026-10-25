//go:build !windows

package cpuclock

// New prepara la lettura della frequenza: fuori da Windows non ci sono i
// contatori, e ogni lettura restituisce ErrUnavailable.
func New() *Sampler { return &Sampler{Open: Open} }

// Open non è disponibile fuori da Windows.
func Open() (Source, error) { return nil, ErrUnavailable }
