package pcinfo

import (
	"context"
	"time"
)

// within esegue f con un tempo massimo e ne restituisce il risultato; se f
// non finisce nemmeno 2 secondi dopo la scadenza (una chiamata di Windows
// bloccata non si interrompe) restituisce false e la abbandona. f non deve
// scrivere dati condivisi: il risultato passa solo dal valore restituito.
func within[T any](ctx context.Context, d time.Duration, f func(context.Context) T) (T, bool) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	ch := make(chan T, 1)
	go func() { ch <- f(ctx) }()
	select {
	case v := <-ch:
		return v, true
	case <-ctx.Done():
	}
	select {
	case v := <-ch:
		return v, true
	case <-time.After(2 * time.Second):
		var zero T
		return zero, false
	}
}
