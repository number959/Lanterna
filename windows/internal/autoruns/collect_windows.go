//go:build windows

package autoruns

import (
	"context"
	"errors"
	"os"
	"sort"
	"time"

	"lanterna/internal/pcinfo"
	"lanterna/internal/scan"
	"lanterna/internal/sign"
	"lanterna/internal/winapi"
)

// Tempi: le sorgenti e la verifica delle firme si fermano 3 secondi prima
// della scadenza del chiamante (la fase dell'analisi ne concede 45), più 2
// secondi di margine per una chiamata di Windows che non risponde.
const (
	reserve = 3 * time.Second
	grace   = 2 * time.Second
	workers = 4
)

// Collect legge tutto ciò che si avvia da solo. Non fallisce se una parte
// non si legge: restituisce il resto, con Denied e Partial, e un errore che
// spiega le parti mancate (nil se tutto è andato bene).
func Collect(ctx context.Context) (*scan.AutorunsData, error) {
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dl.Add(-reserve))
		defer cancel()
	}
	profile := os.Getenv("USERPROFILE")
	rd := reader{
		res: Resolver{Getenv: os.Getenv, Exists: func(p string) bool {
			st, err := os.Stat(p)
			return err == nil && !st.IsDir()
		}},
		cl: cleaner{profile: profile, user: os.Getenv("USERNAME")},
	}
	checker := sign.New(profile, func(p string) string { return pcinfo.SanitizeCommand(p, profile) })
	facts := func(ctx context.Context, p string) *scan.FileFacts {
		f := checker.Facts(ctx, p)
		f.Path = rd.cl.text(f.Path)
		return f
	}
	plain := func(p string) *scan.FileFacts {
		return &scan.FileFacts{Path: rd.cl.path(p), Folder: sign.FolderOf(p, profile)}
	}
	sources := []source{
		{"registry", func(ctx context.Context) sourceResult { return readRegistry(ctx, rd) }},
		{"services", func(ctx context.Context) sourceResult { return readServices(ctx, rd) }},
		{"tasks", func(ctx context.Context) sourceResult { return readTasks(ctx, rd) }},
		{"wmi", func(ctx context.Context) sourceResult { return readWMI(ctx, rd) }},
		{"browser", func(ctx context.Context) sourceResult { return readBrowsers(ctx, rd) }},
	}
	items, denied, errs, partial := gather(ctx, sources, facts, plain, workers, grace)
	out := &scan.AutorunsData{Elevated: winapi.Elevated(), Partial: partial}
	out.Entries, out.Counts = assemble(items)
	seen := map[string]bool{}
	for _, d := range denied {
		if !seen[d] {
			seen[d] = true
			out.Denied = append(out.Denied, d)
		}
	}
	sort.Strings(out.Denied)
	if partial {
		errs = append(errs, errors.New("tempo scaduto: elenco o verifica delle firme incompleti"))
	}
	return out, errors.Join(errs...)
}
