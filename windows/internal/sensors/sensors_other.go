//go:build !windows

package sensors

// New prepara il monitor dei sensori: fuori da Windows non ci sono le fonti,
// e ogni lettura restituisce ErrUnavailable.
func New() *Monitor { return &Monitor{Open: Open} }

// Open non è disponibile fuori da Windows.
func Open() (Source, error) { return nil, ErrUnavailable }
