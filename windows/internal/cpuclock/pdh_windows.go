//go:build windows

package cpuclock

import (
	"errors"
	"fmt"
	"math"

	"golang.org/x/sys/windows/registry"

	"lanterna/internal/pdh"
)

// Percorsi in inglese: PdhAddEnglishCounterW li accetta con Windows in
// qualunque lingua (i nomi localizzati cambiano, per esempio, in italiano).
const (
	pathPerf = `\Processor Information(*)\% Processor Performance`
	pathFreq = `\Processor Information(*)\Processor Frequency`
	pathLoad = `\Processor Information(*)\% Processor Time`
)

type pdhSource struct {
	q                *pdh.Query
	perf, freq, load pdh.Counter
}

// New prepara la lettura della frequenza, con la frequenza nominale scritta
// da Windows nel registro come riserva.
func New() *Sampler {
	return &Sampler{Open: Open, Fallback: registryMHz()}
}

func registryMHz() float64 {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err != nil {
		return 0
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("~MHz")
	if err != nil {
		return 0
	}
	return float64(v)
}

// Open apre i contatori delle prestazioni del processore.
func Open() (Source, error) {
	q, err := pdh.Open()
	if errors.Is(err, pdh.ErrUnavailable) {
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, err
	}
	s := &pdhSource{q: q}
	if s.perf, err = q.Add(pathPerf); err != nil {
		q.Close()
		return nil, fmt.Errorf("%w (%v)", ErrUnavailable, err)
	}
	// Senza la frequenza nominale per istanza si usa quella del registro.
	if s.freq, err = q.Add(pathFreq); err != nil {
		s.freq = 0
	}
	// Il carico è facoltativo.
	if s.load, err = q.Add(pathLoad); err != nil {
		s.load = 0
	}
	return s, nil
}

func (s *pdhSource) Collect() error { return s.q.Collect() }

func (s *pdhSource) Read() (map[string]Reading, error) {
	out := map[string]Reading{}
	put := func(c pdh.Counter, set func(*Reading, float64)) error {
		if c == 0 {
			return nil
		}
		vals, err := s.q.Values(c)
		if err != nil {
			return err
		}
		for name, v := range vals {
			x, ok := out[name]
			if !ok {
				x = Reading{Perf: math.NaN(), Freq: math.NaN(), Load: math.NaN()}
			}
			set(&x, v)
			out[name] = x
		}
		return nil
	}
	if err := put(s.perf, func(x *Reading, v float64) { x.Perf = v }); err != nil {
		return nil, err
	}
	_ = put(s.freq, func(x *Reading, v float64) { x.Freq = v })
	_ = put(s.load, func(x *Reading, v float64) { x.Load = v })
	return out, nil
}

func (s *pdhSource) Close() { s.q.Close() }
