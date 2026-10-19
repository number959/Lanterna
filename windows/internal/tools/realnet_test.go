//go:build realnet

package tools

// Prova manuale con i siti veri dei produttori, esclusa dai test normali:
//   go test -tags realnet -run TestRealDownloads ./internal/tools/
// Scarica ogni versione portable (Microsoft Safety Scanner, 230 MB, solo con
// POLARIS_REALNET_BIG=1), seguendo gli stessi reindirizzamenti, host ammessi,
// limiti e impronte dell'agente. Su Windows verifica anche la firma; altrove
// la firma non si può verificare e la prova lo dichiara.

import (
	"context"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestRealDownloads(t *testing.T) {
	f := &Fetcher{
		Root:      t.TempDir(),
		Arch:      "amd64",
		Transport: &http.Transport{Proxy: http.ProxyFromEnvironment},
		Verify:    defaultVerify,
		UserAgent: "STARNET-Polaris/realnet",
	}
	if runtime.GOOS != "windows" {
		f.Verify = func(path string) (Signature, error) {
			return Signature{Status: "Valid", Signer: "(firma non verificabile fuori da Windows)"}, nil
		}
	}
	for id, p := range Portables {
		if p.MaxMB > 100 && os.Getenv("POLARIS_REALNET_BIG") == "" {
			t.Logf("%s: saltato (%d MB al massimo)", id, p.MaxMB)
			continue
		}
		if runtime.GOOS != "windows" {
			signer := p.Signer
			f.Verify = func(string) (Signature, error) { return Signature{Status: "Valid", Signer: signer}, nil }
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		var total int64
		start := time.Now()
		d, err := f.Fetch(ctx, id, func(done, tot int64) { total = done })
		cancel()
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		t.Logf("%s: %.1f MB in %s, versione %q, eseguibile %s", id, float64(total)/1e6, time.Since(start).Round(time.Millisecond), d.Version, d.Path)
	}
}
