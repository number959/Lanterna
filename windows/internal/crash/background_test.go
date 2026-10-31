package crash

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lanterna/internal/scan"
)

func TestBackgroundInTime(t *testing.T) {
	want := &scan.CrashData{Folder: "ok", Total: 1, Dumps: []scan.CrashDump{{File: "a.dmp"}}}
	b := Start(context.Background(), time.Second, func(context.Context) (*scan.CrashData, error) { return want, nil })
	if got := b.Wait(time.Second, time.Second); got != want {
		t.Fatalf("risultato: %+v", got)
	}
	// Fuori da Windows la lettura non c'è: nil, non un risultato vuoto.
	b = Start(context.Background(), time.Second, func(context.Context) (*scan.CrashData, error) { return nil, ErrUnavailable })
	if got := b.Wait(time.Second, time.Second); got != nil {
		t.Fatalf("non disponibile: %+v", got)
	}
}

// Una lettura lenta che rispetta il contesto si ferma tra un file e l'altro
// e consegna ciò che ha già letto, segnato come parziale.
func TestBackgroundStopsAndKeepsPartial(t *testing.T) {
	f := &fakeSys{files: map[string]fakeFile{}}
	for i, name := range []string{"092026-1-01.dmp", "092126-1-01.dmp", "092226-1-01.dmp"} {
		x := fxTriage(0xD1, [4]uint64{0, 2, 0, fxNet.base + 0x10})
		x.time = day(20 + i)
		f.files[name] = fakeFile{data: x.bytes(), mod: day(20 + i)}
	}
	release := make(chan struct{})
	sys := f.system()
	open := sys.Open
	opened := 0
	sys.Open = func(p string) (File, error) {
		opened++
		if opened == 2 {
			<-release // il secondo file "resta bloccato" finché non si chiede di fermarsi
		}
		return open(p)
	}
	read := func(ctx context.Context) (*scan.CrashData, error) {
		go func() {
			<-ctx.Done()
			close(release)
		}()
		return Collect(ctx, sys), nil
	}
	got := Start(context.Background(), time.Minute, read).Wait(20*time.Millisecond, 5*time.Second)
	if got == nil || !got.Partial || got.Folder != "ok" || got.Total != 3 || len(got.Dumps) != 2 {
		t.Fatalf("lettura parziale: %+v", got)
	}
}

// Una lettura che non risponde nemmeno dopo la richiesta di fermarsi (una
// cartella di rete irraggiungibile) lascia un risultato vuoto e parziale,
// mai nil: l'interfaccia dice che la lettura non è finita in tempo.
func TestBackgroundStuck(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	b := Start(context.Background(), time.Minute, func(context.Context) (*scan.CrashData, error) {
		<-release
		return &scan.CrashData{Folder: "ok"}, nil
	})
	start := time.Now()
	got := b.Wait(10*time.Millisecond, 10*time.Millisecond)
	if time.Since(start) > 2*time.Second {
		t.Fatal("attesa troppo lunga")
	}
	if got == nil || !got.Partial || got.Folder != "" || got.Settings != nil || got.Dumps == nil || got.ReadAt == "" {
		t.Fatalf("risultato di riserva: %+v", got)
	}
	b2, _ := json.Marshal(got)
	if !strings.Contains(string(b2), `"dumps":[]`) || !strings.Contains(string(b2), `"partial":true`) {
		t.Fatalf("JSON: %s", b2)
	}
}
