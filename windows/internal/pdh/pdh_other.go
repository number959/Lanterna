//go:build !windows

package pdh

// Query non è disponibile fuori da Windows.
type Query struct{}

// Open restituisce sempre ErrUnavailable fuori da Windows.
func Open() (*Query, error) { return nil, ErrUnavailable }

// Add non è disponibile fuori da Windows.
func (q *Query) Add(string) (Counter, error) { return 0, ErrUnavailable }

// Collect non è disponibile fuori da Windows.
func (q *Query) Collect() error { return ErrUnavailable }

// Values non è disponibile fuori da Windows.
func (q *Query) Values(Counter) (map[string]float64, error) { return nil, ErrUnavailable }

// Close non fa nulla fuori da Windows.
func (q *Query) Close() {}
