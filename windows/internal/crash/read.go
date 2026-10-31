package crash

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"lanterna/internal/scan"
)

const (
	// MaxFiles è il numero massimo di minidump letti, i più recenti.
	MaxFiles = 50
	// MaxParseBytes: oltre questa dimensione un minidump (normalmente da
	// poche centinaia di KB a qualche MB) si legge solo nell'intestazione.
	MaxParseBytes = 64 << 20
)

// ErrUnavailable: la lettura delle schermate blu esiste solo su Windows.
var ErrUnavailable = errors.New("lettura delle schermate blu disponibile solo su Windows")

// File è un file aperto in sola lettura.
type File interface {
	io.ReaderAt
	io.Closer
}

// Entry descrive un file di una cartella.
type Entry struct {
	Name string
	Size int64
	Mod  time.Time
	Dir  bool
}

// System raccoglie ciò che dipende da Windows (registro, cartelle, file),
// così la logica si collauda su qualunque sistema. Gli errori di permesso
// devono soddisfare errors.Is(err, fs.ErrPermission), quelli di file
// mancante errors.Is(err, fs.ErrNotExist).
type System struct {
	// Settings legge CrashControl: le impostazioni da mostrare e i percorsi
	// effettivi della cartella dei minidump e di MEMORY.DMP.
	Settings func() (s *scan.CrashSettings, minidumpDir, dumpFile string)
	ReadDir  func(dir string) ([]Entry, error)
	Stat     func(path string) (Entry, error)
	Open     func(path string) (File, error)
	Now      func() time.Time
}

// Collect legge impostazioni, minidump e intestazione di MEMORY.DMP. Non
// fallisce mai: ciò che non si legge (di solito per i permessi) è indicato
// nei campi Folder, NeedsAdmin ed Error.
func Collect(ctx context.Context, sys System) *scan.CrashData {
	now := time.Now
	if sys.Now != nil {
		now = sys.Now
	}
	d := &scan.CrashData{ReadAt: now().UTC().Format(time.RFC3339), Dumps: []scan.CrashDump{}}
	var mdir, dfile string
	if sys.Settings != nil {
		d.Settings, mdir, dfile = sys.Settings()
	}

	if mdir != "" {
		entries, err := sys.ReadDir(mdir)
		switch {
		case err == nil:
			d.Folder = "ok"
		case errors.Is(err, fs.ErrNotExist):
			d.Folder = "missing"
		case errors.Is(err, fs.ErrPermission):
			d.Folder, d.NeedsAdmin = "denied", true
		default:
			d.Folder = "error"
		}
		var files []Entry
		for _, e := range entries {
			if !e.Dir && strings.EqualFold(filepath.Ext(e.Name), ".dmp") {
				files = append(files, e)
			}
		}
		sort.SliceStable(files, func(i, j int) bool { return files[i].Mod.After(files[j].Mod) })
		d.Total = len(files)
		if len(files) > MaxFiles {
			files = files[:MaxFiles]
		}
		for _, f := range files {
			if ctx.Err() != nil {
				d.Partial = true
				break
			}
			cd := readFile(sys, filepath.Join(mdir, f.Name), f, f.Size > MaxParseBytes)
			if cd.Error == errDenied {
				d.NeedsAdmin = true
			}
			d.Dumps = append(d.Dumps, cd)
		}
		sort.SliceStable(d.Dumps, func(i, j int) bool { return when(d.Dumps[i]) > when(d.Dumps[j]) })
	}

	if dfile != "" && ctx.Err() == nil && sys.Stat != nil {
		if fi, err := sys.Stat(dfile); err == nil && !fi.Dir {
			cd := readFile(sys, dfile, fi, true)
			if cd.Error == errDenied {
				d.NeedsAdmin = true
			}
			d.MemoryDump = &cd
		} else if errors.Is(err, fs.ErrPermission) {
			d.NeedsAdmin = true
		}
	} else if dfile != "" && ctx.Err() != nil {
		d.Partial = true
	}
	return d
}

// when è l'ora dell'arresto, o la data del file se manca (RFC 3339 in UTC:
// l'ordine alfabetico è quello cronologico).
func when(c scan.CrashDump) string {
	if c.Time != "" {
		return c.Time
	}
	return c.Modified
}

const (
	errDenied  = "accesso negato: serve avviare Polaris come amministratore"
	errGone    = "file non più presente"
	errUnread  = "file non leggibile"
	errBadDump = "non è un file di dump di Windows"
	errShort   = "file troncato o danneggiato: intestazione incompleta"
)

// errText traduce un errore senza mai riportare il percorso del file.
func errText(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return errDenied
	case errors.Is(err, fs.ErrNotExist):
		return errGone
	case errors.Is(err, ErrNotDump):
		return errBadDump
	case errors.Is(err, ErrTruncated):
		return errShort
	}
	return errUnread
}

// readFile legge un file di dump; headerOnly per MEMORY.DMP e per i
// minidump troppo grandi.
func readFile(sys System, path string, fi Entry, headerOnly bool) scan.CrashDump {
	cd := scan.CrashDump{File: BaseName(fi.Name), Size: fi.Size}
	if cd.File == "" {
		cd.File = BaseName(path)
	}
	if !fi.Mod.IsZero() {
		cd.Modified = fi.Mod.UTC().Format(time.RFC3339)
	}
	f, err := sys.Open(path)
	if err != nil {
		cd.Error = errText(err)
		return cd
	}
	defer f.Close()
	dump, err := Parse(f, fi.Size, Options{HeaderOnly: headerOnly})
	if err != nil {
		cd.Error = errText(err)
		return cd
	}
	fill(&cd, dump)
	return cd
}

// fill copia nel formato dei rapporti i dati di un dump analizzato.
func fill(cd *scan.CrashDump, d *Dump) {
	cd.Bits = d.Bits
	cd.Machine = MachineName(d.Machine)
	cd.Build = d.Build
	cd.Processors = d.Processors
	cd.DumpType = TypeName(d.DumpType, d.TypeSet)
	if !d.Time.IsZero() {
		cd.Time = d.Time.Format(time.RFC3339)
	}
	if d.CodeSet {
		cd.Code = fmt.Sprintf("0x%08x", d.Code)
		width := 16
		if d.Bits == 32 {
			width = 8
		}
		cd.Params = make([]string, 4)
		for i := range cd.Params {
			if d.ParamSet[i] {
				cd.Params[i] = fmt.Sprintf("0x%0*x", width, d.Params[i])
			}
		}
	}
	cd.Drivers = len(d.Drivers)
	if p := d.Probable; p != nil {
		cd.Probable = &scan.CrashCulprit{Driver: p.Module.Name, Method: p.Method, Param: p.Param, Offset: fmt.Sprintf("0x%x", p.Offset), Unloaded: p.Module.Unloaded}
	}
	if len(d.StackModules) > 0 {
		cd.Stack = append([]string(nil), d.StackModules...)
	}
	cd.Limited = d.Limited
}

// genericProfiles sono cartelle dei profili che non sono persone.
var genericProfiles = map[string]bool{"public": true, "default": true, "default user": true, "all users": true}

var profilesRE = regexp.MustCompile(`(?i)(\\(?:Users|Documents and Settings)\\)([^\\]+)`)

// DisplayPath prepara un percorso del registro per i rapporti: la cartella
// del profilo di chi usa Polaris diventa %USERPROFILE% e i nomi degli altri
// profili ‹utente›. Le variabili come %SystemRoot% restano come sono.
func DisplayPath(p, profile string) string {
	p = strings.TrimSpace(p)
	if prof := strings.TrimRight(profile, `\`); len(prof) > 3 {
		low, lp := strings.ToLower(p), strings.ToLower(prof)
		var b strings.Builder
		for {
			i := strings.Index(low, lp)
			// Solo come cartella intera: C:\Users\anna, non C:\Users\annamaria.
			if i < 0 || i+len(lp) < len(low) && low[i+len(lp)] != '\\' {
				b.WriteString(p)
				break
			}
			b.WriteString(p[:i])
			b.WriteString("%USERPROFILE%")
			p, low = p[i+len(lp):], low[i+len(lp):]
		}
		p = b.String()
	}
	return profilesRE.ReplaceAllStringFunc(p, func(m string) string {
		sub := profilesRE.FindStringSubmatch(m)
		if genericProfiles[strings.ToLower(sub[2])] || strings.HasPrefix(sub[2], "%") {
			return m
		}
		return sub[1] + "‹utente›"
	})
}
