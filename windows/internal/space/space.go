// Package space dice che cosa occupa spazio su un'unità, come WizTree: legge
// l'elenco delle cartelle (non il contenuto dei file) con più lettori in
// parallelo e restituisce le cartelle più grandi, i file più grandi, i tipi
// di file e le cartelle note che si possono ripulire. Non legge la tabella
// dei file di NTFS (servirebbero i permessi di amministratore e l'accesso
// diretto al volume): è più lento di WizTree ma funziona su ogni file system
// e rispetta i permessi delle cartelle.
//
// Lo spazio contato è quello occupato sul disco: i file solo online di
// OneDrive valgono zero e i collegamenti fisici della cartella di Windows
// (WinSxS e System32 condividono gli stessi file) si contano una volta. I
// percorsi restituiti non contengono nomi utente.
package space

import (
	"container/heap"
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lanterna/internal/scan"
)

// ErrUnavailable: analisi non disponibile su questo sistema.
var ErrUnavailable = errors.New("analisi dello spazio non disponibile su questo sistema")

// entry è una voce dell'elenco di una cartella.
type entry struct {
	Name  string
	Dir   bool
	Alloc int64 // spazio occupato sul disco
	Size  int64 // dimensione dei dati
	Attrs uint32
	Tag   uint32 // tag del punto di reparse, se Attrs lo indica
	ID    uint64 // numero di riferimento del file (0: non noto)
	Mod   int64  // ultima modifica, secondi Unix
}

// lister legge l'elenco di una cartella, senza "." e "..".
type lister interface {
	List(path string) ([]entry, error)
}

// Attributi dei file (winnt.h).
const (
	attrReparse            = 0x00000400
	attrOffline            = 0x00001000
	attrRecallOnDataAccess = 0x00400000
	// Bit "name surrogate" dei tag: collegamenti simbolici, giunzioni e punti
	// di montaggio rimandano ad altro e non si seguono.
	tagNameSurrogate = 0x20000000
)

// follow dice se scendere in una sottocartella: non nei collegamenti
// (giunzioni, collegamenti simbolici, punti di montaggio), sì nelle cartelle
// con altri punti di reparse, come quelle di OneDrive.
func follow(e entry) bool {
	return e.Dir && (e.Attrs&attrReparse == 0 || e.Tag&tagNameSurrogate == 0)
}

// cloudOnly: file solo online, i cui dati non sono sul disco.
func cloudOnly(e entry) bool { return e.Attrs&(attrRecallOnDataAccess|attrOffline) != 0 }

// Env sono i percorsi del PC che servono a riconoscere le cartelle note e a
// togliere i nomi utente dai percorsi. I percorsi sono completi ("C:\Users\x").
type Env struct {
	SystemRoot   string
	Temp         string
	LocalAppData string
	ProgramData  string
	UserProfile  string
	OneDrive     string
	Username     string
	// ProfilesDir è la cartella dei profili ("C:\Users"); OtherProfiles i
	// nomi degli altri profili che vi si trovano.
	ProfilesDir   string
	OtherProfiles []string
}

// Options regola l'analisi.
type Options struct {
	// Workers: lettori in parallelo (8).
	Workers int
	// TreeNodes: cartelle al massimo nell'albero del rapporto (1500).
	TreeNodes int
	// TopFiles: quanti file più grandi riportare (100).
	TopFiles int
	// Progress riceve l'avanzamento circa quattro volte al secondo.
	Progress func(Progress)
	Now      func() time.Time
}

// Progress è l'avanzamento dell'analisi.
type Progress struct {
	Dirs      int64 `json:"dirs"`
	Files     int64 `json:"files"`
	Alloc     int64 `json:"alloc"`
	ElapsedMs int64 `json:"elapsedMs"`
}

// Result è il rapporto, con i percorsi veri delle cartelle e dei file che
// contiene (per aprirli in Esplora file: restano nell'agente).
type Result struct {
	Report    scan.SpaceReport
	NodePaths map[int]string
	FilePaths map[int]string
}

// Volume descrive l'unità analizzata.
type Volume struct {
	Drive      string // "C:"
	FS         string
	TotalBytes int64
	FreeBytes  int64
}

// node è una cartella durante l'analisi.
type node struct {
	name     string
	parent   *node
	children []*node
	ownAlloc int64
	ownSize  int64
	ownFiles int64
	alloc    int64
	size     int64
	files    int64
	dirs     int64
	denied   bool
	// win: dentro la cartella di Windows, dove si tengono i numeri dei file
	// per riconoscere i collegamenti fisici.
	win bool
}

type fileRec struct {
	n     *node
	name  string
	alloc int64
	size  int64
	mod   int64
	id    uint64
	cloud bool
}

type linkRec struct {
	id    uint64
	n     *node
	name  string
	alloc int64
	size  int64
	ext   string
}

type typeAcc struct{ alloc, files int64 }

// topHeap tiene i file più grandi (minimo in cima).
type topHeap []fileRec

func (h topHeap) Len() int { return len(h) }
func (h topHeap) Less(i, j int) bool {
	if h[i].alloc != h[j].alloc {
		return h[i].alloc < h[j].alloc
	}
	return h[i].name > h[j].name
}
func (h topHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *topHeap) Push(x any)   { *h = append(*h, x.(fileRec)) }
func (h *topHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// acc raccoglie i dati di un lettore, senza blocchi.
type acc struct {
	exts       map[string]*typeAcc
	top        topHeap
	links      []linkRec
	known      []fileRec // file noti nella radice e nella cartella di Windows
	denied     []*node
	cloudFiles int64
	cloudBytes int64
}

type job struct {
	n    *node
	path string
}

// queue è la coda delle cartelle da leggere: pending conta quelle non ancora
// finite, così i lettori sanno quando non ci sarà più lavoro.
type queue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	items   []job
	pending int
	stop    bool
}

func newQueue() *queue {
	q := &queue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *queue) push(j job) {
	q.mu.Lock()
	q.items = append(q.items, j)
	q.pending++
	q.mu.Unlock()
	q.cond.Signal()
}

func (q *queue) pop() (job, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.items) == 0 && q.pending > 0 && !q.stop {
		q.cond.Wait()
	}
	if q.stop || len(q.items) == 0 {
		return job{}, false
	}
	// Dall'ultima: si scende in profondità e la coda resta corta.
	j := q.items[len(q.items)-1]
	q.items = q.items[:len(q.items)-1]
	return j, true
}

func (q *queue) done() {
	q.mu.Lock()
	q.pending--
	last := q.pending == 0
	q.mu.Unlock()
	if last {
		q.cond.Broadcast()
	}
}

func (q *queue) halt() {
	q.mu.Lock()
	q.stop = true
	q.mu.Unlock()
	q.cond.Broadcast()
}

// join unisce un percorso e un nome ("C:\" + "Windows" = "C:\Windows").
func join(dir, name string) string {
	if strings.HasSuffix(dir, `\`) {
		return dir + name
	}
	return dir + `\` + name
}

func under(path, dir string) bool {
	if dir == "" {
		return false
	}
	lp, ld := strings.ToLower(path), strings.TrimSuffix(strings.ToLower(dir), `\`)
	return lp == ld || strings.HasPrefix(lp, ld+`\`)
}

// fullPath ricostruisce il percorso di una cartella dai genitori.
func fullPath(n *node) string {
	var parts []string
	for x := n; x != nil; x = x.parent {
		parts = append(parts, x.name)
	}
	p := parts[len(parts)-1]
	for i := len(parts) - 2; i >= 0; i-- {
		p = join(p, parts[i])
	}
	return p
}

// extOf restituisce l'estensione in minuscolo (".mp4"), vuota se non c'è.
func extOf(name string) string {
	i := strings.LastIndexByte(name, '.')
	if i <= 0 || i == len(name)-1 || len(name)-i > 11 || strings.ContainsAny(name[i:], " ") {
		return ""
	}
	return strings.ToLower(name[i:])
}

// categories associa le estensioni più comuni a una categoria.
var categories = func() map[string]string {
	m := map[string]string{}
	for cat, exts := range map[string]string{
		"video":       ".mp4 .mkv .avi .mov .wmv .m4v .webm .mpg .mpeg .flv .ts .m2ts .mts .3gp .vob",
		"image":       ".jpg .jpeg .png .gif .bmp .tif .tiff .heic .heif .webp .raw .cr2 .cr3 .nef .arw .dng .orf .psd .svg .ico",
		"audio":       ".mp3 .wav .flac .aac .m4a .ogg .wma .opus .aiff .aif .mid .midi",
		"document":    ".pdf .doc .docx .xls .xlsx .xlsm .ppt .pptx .odt .ods .odp .txt .rtf .csv .md .pst .ost .one .epub .msg .eml .accdb .mdb",
		"archive":     ".zip .rar .7z .tar .gz .tgz .bz2 .xz .zst .iso .img .cab .wim .esd",
		"program":     ".exe .dll .msi .msix .msixbundle .appx .appxbundle .sys .ocx .mui .pak .jar .so .node .pdb",
		"virtualdisk": ".vhd .vhdx .avhdx .vmdk .vdi .qcow2",
	} {
		for _, e := range strings.Fields(exts) {
			m[e] = cat
		}
	}
	return m
}()

// systemFiles sono i file di sistema riconosciuti per nome: nelle
// statistiche compaiono con il nome invece che con l'estensione (".sys"
// li confonderebbe con i driver).
var systemFiles = map[string]bool{"pagefile.sys": true, "hiberfil.sys": true, "swapfile.sys": true, "memory.dmp": true}

// typeKey è la chiave delle statistiche per tipo: il nome per i file di
// sistema noti, altrimenti l'estensione.
func typeKey(name string) string {
	if l := strings.ToLower(name); systemFiles[l] {
		return l
	}
	return extOf(name)
}

func categoryOf(key string) string {
	if systemFiles[key] {
		return "system"
	}
	if c, found := categories[key]; found {
		return c
	}
	return "other"
}

// Scan analizza la cartella root (di solito la radice di un'unità, "C:\").
// Con il contesto annullato restituisce ciò che ha letto fino a quel
// momento, con Partial, e l'errore del contesto.
func scanWith(ctx context.Context, l lister, root string, vol Volume, env Env, opt Options) (*Result, error) {
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	start := now()
	workers := opt.Workers
	if workers <= 0 {
		workers = 8
	}
	rootNode := &node{name: root}
	rootNode.win = under(root, env.SystemRoot)
	sysRoot := strings.ToLower(env.SystemRoot)
	var dirs, files, alloc atomic.Int64
	q := newQueue()
	q.push(job{rootNode, root})
	accs := make([]*acc, workers)
	var wg sync.WaitGroup
	topN := opt.TopFiles
	if topN <= 0 {
		topN = 100
	}
	for w := range workers {
		a := &acc{exts: map[string]*typeAcc{}}
		accs[w] = a
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				j, ok := q.pop()
				if !ok {
					return
				}
				if ctx.Err() == nil {
					readDir(l, j, a, q, topN, rootNode, sysRoot, &dirs, &files, &alloc)
				}
				q.done()
			}
		}()
	}
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				q.halt()
				return
			case <-stopWatch:
				return
			case <-t.C:
				if opt.Progress != nil {
					opt.Progress(Progress{Dirs: dirs.Load(), Files: files.Load(), Alloc: alloc.Load(), ElapsedMs: now().Sub(start).Milliseconds()})
				}
			}
		}
	}()
	wg.Wait()
	close(stopWatch)
	<-watchDone
	if opt.Progress != nil {
		opt.Progress(Progress{Dirs: dirs.Load(), Files: files.Load(), Alloc: alloc.Load(), ElapsedMs: now().Sub(start).Milliseconds()})
	}
	res := build(rootNode, accs, root, vol, env, opt, topN)
	res.Report.StartedAt = start.UTC().Format(time.RFC3339)
	res.Report.DurationMs = now().Sub(start).Milliseconds()
	if err := ctx.Err(); err != nil {
		res.Report.Partial = true
		return res, err
	}
	return res, nil
}

func readDir(l lister, j job, a *acc, q *queue, topN int, root *node, sysRoot string, dirs, files, alloc *atomic.Int64) {
	ents, err := l.List(j.path)
	if err != nil {
		j.n.denied = true
		a.denied = append(a.denied, j.n)
		return
	}
	known := j.n == root || strings.ToLower(j.path) == sysRoot
	for _, e := range ents {
		if e.Dir {
			if !follow(e) {
				continue
			}
			p := join(j.path, e.Name)
			child := &node{name: e.Name, parent: j.n, win: j.n.win || (sysRoot != "" && strings.ToLower(p) == sysRoot)}
			j.n.children = append(j.n.children, child)
			dirs.Add(1)
			q.push(job{child, p})
			continue
		}
		size := max(e.Size, 0)
		fa := max(e.Alloc, 0)
		j.n.ownAlloc += fa
		j.n.ownSize += size
		j.n.ownFiles++
		files.Add(1)
		alloc.Add(fa)
		cloud := cloudOnly(e)
		if cloud {
			a.cloudFiles++
			a.cloudBytes += size
		}
		ext := typeKey(e.Name)
		t := a.exts[ext]
		if t == nil {
			t = &typeAcc{}
			a.exts[ext] = t
		}
		t.alloc += fa
		t.files++
		rec := fileRec{n: j.n, name: e.Name, alloc: fa, size: size, mod: e.Mod, id: e.ID, cloud: cloud}
		if len(a.top) < topN {
			heap.Push(&a.top, rec)
		} else if a.top.Len() > 0 && (fa > a.top[0].alloc || fa == a.top[0].alloc && e.Name < a.top[0].name) {
			a.top[0] = rec
			heap.Fix(&a.top, 0)
		}
		if j.n.win && e.ID != 0 {
			a.links = append(a.links, linkRec{id: e.ID, n: j.n, name: e.Name, alloc: fa, size: size, ext: ext})
		}
		if known {
			a.known = append(a.known, rec)
		}
	}
}

// build unisce i dati dei lettori e prepara il rapporto.
func build(root *node, accs []*acc, rootPath string, vol Volume, env Env, opt Options, topN int) *Result {
	z := newSanitizer(env)
	r := scan.SpaceReport{Root: z.path(rootPath), Drive: vol.Drive, FS: vol.FS, TotalBytes: vol.TotalBytes, FreeBytes: vol.FreeBytes}
	exts := map[string]*typeAcc{}
	var top []fileRec
	var links []linkRec
	var known []fileRec
	var denied []*node
	for _, a := range accs {
		for k, v := range a.exts {
			t := exts[k]
			if t == nil {
				t = &typeAcc{}
				exts[k] = t
			}
			t.alloc += v.alloc
			t.files += v.files
		}
		top = append(top, a.top...)
		links = append(links, a.links...)
		known = append(known, a.known...)
		denied = append(denied, a.denied...)
		r.CloudFiles += a.cloudFiles
		r.CloudBytes += a.cloudBytes
	}
	r.LinkedBytes = dedupeLinks(links, exts)
	totals(root)
	r.AllocBytes, r.SizeBytes, r.Files, r.Dirs = root.alloc, root.size, root.files, root.dirs
	r.Denied = int64(len(denied))
	sort.Slice(denied, func(i, j int) bool {
		di, dj := depth(denied[i]), depth(denied[j])
		if di != dj {
			return di < dj
		}
		return fullPath(denied[i]) < fullPath(denied[j])
	})
	for _, d := range denied[:min(10, len(denied))] {
		r.DeniedPaths = append(r.DeniedPaths, z.path(fullPath(d)))
	}
	res := &Result{NodePaths: map[int]string{}, FilePaths: map[int]string{}}
	limit := opt.TreeNodes
	if limit <= 0 {
		limit = 1500
	}
	ids := map[*node]int{}
	r.Tree = prune(root, limit, z, res.NodePaths, ids)
	r.TopFiles = topFiles(top, topN, z, res.FilePaths)
	r.Types, r.Categories = typeStats(exts)
	r.Hints = hints(root, known, exts, rootPath, env, z, ids)
	res.Report = r
	return res
}

func depth(n *node) int {
	d := 0
	for x := n; x.parent != nil; x = x.parent {
		d++
	}
	return d
}

// dedupeLinks conta una volta sola i file con più nomi (collegamenti fisici)
// nella cartella di Windows: il file resta nella cartella con il percorso
// che viene prima in ordine alfabetico, così il risultato non dipende
// dall'ordine di lettura. Restituisce lo spazio non contato due volte.
func dedupeLinks(links []linkRec, exts map[string]*typeAcc) int64 {
	if len(links) < 2 {
		return 0
	}
	paths := map[*node]string{}
	key := func(l linkRec) string {
		p, found := paths[l.n]
		if !found {
			p = strings.ToLower(fullPath(l.n))
			paths[l.n] = p
		}
		return p + `\` + strings.ToLower(l.name)
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].id != links[j].id {
			return links[i].id < links[j].id
		}
		return key(links[i]) < key(links[j])
	})
	var saved int64
	for i := 1; i < len(links); i++ {
		if links[i].id != links[i-1].id {
			continue
		}
		// Copia ulteriore dello stesso file: si toglie dalla sua cartella.
		l := links[i]
		l.n.ownAlloc -= l.alloc
		l.n.ownSize -= l.size
		l.n.ownFiles--
		if t := exts[l.ext]; t != nil {
			t.alloc -= l.alloc
			t.files--
		}
		saved += l.alloc
	}
	return saved
}

// totals calcola i totali di ogni cartella dal basso e restituisce le
// cartelle in ordine dalla radice.
func totals(root *node) []*node {
	order := []*node{root}
	for i := 0; i < len(order); i++ {
		order = append(order, order[i].children...)
	}
	for i := len(order) - 1; i >= 0; i-- {
		n := order[i]
		n.alloc += n.ownAlloc
		n.size += n.ownSize
		n.files += n.ownFiles
		if p := n.parent; p != nil {
			p.alloc += n.alloc
			p.size += n.size
			p.files += n.files
			p.dirs += n.dirs + 1
		}
	}
	return order
}

func sortChildren(n *node) []*node {
	c := append([]*node(nil), n.children...)
	sort.Slice(c, func(i, j int) bool {
		if c[i].alloc != c[j].alloc {
			return c[i].alloc > c[j].alloc
		}
		return strings.ToLower(c[i].name) < strings.ToLower(c[j].name)
	})
	return c
}

// expansion è una cartella in attesa di essere dettagliata nell'albero.
type expansion struct {
	n   *node
	out *scan.SpaceNode
}

type expHeap []expansion

func (h expHeap) Len() int { return len(h) }
func (h expHeap) Less(i, j int) bool {
	if h[i].n.alloc != h[j].n.alloc {
		return h[i].n.alloc > h[j].n.alloc
	}
	return h[i].out.ID < h[j].out.ID
}
func (h expHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *expHeap) Push(x any)   { *h = append(*h, x.(expansion)) }
func (h *expHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// prune costruisce l'albero del rapporto: si dettagliano prima le cartelle
// più grandi, fino a limit cartelle; per ognuna si mostrano le sottocartelle
// più grandi (al massimo 40, non sotto un duemillesimo del totale né sotto
// 1 MB) e le altre si riassumono.
func prune(root *node, limit int, z *sanitizer, paths map[int]string, ids map[*node]int) *scan.SpaceNode {
	nextID := 0
	out := func(n *node) *scan.SpaceNode {
		nextID++
		real := fullPath(n)
		paths[nextID] = real
		ids[n] = nextID
		disp := z.path(real)
		name := disp
		if n.parent != nil {
			name = disp[strings.LastIndexByte(disp, '\\')+1:]
		}
		return &scan.SpaceNode{ID: nextID, Name: name, Path: disp, Alloc: n.alloc, Size: n.size, Files: n.files, Dirs: n.dirs, OwnAlloc: n.ownAlloc, OwnFiles: n.ownFiles, Denied: n.denied}
	}
	minShow := max(int64(1<<20), root.alloc/2000)
	top := out(root)
	h := &expHeap{{root, top}}
	count := 1
	summarize := func(e expansion, rest []*node) {
		if len(rest) == 0 {
			return
		}
		m := &scan.SpaceMore{Dirs: int64(len(rest))}
		for _, c := range rest {
			m.Alloc += c.alloc
		}
		e.out.More = m
	}
	for h.Len() > 0 {
		e := heap.Pop(h).(expansion)
		kids := sortChildren(e.n)
		if count >= limit {
			summarize(e, kids)
			continue
		}
		shown := 0
		for _, c := range kids {
			if shown == 40 || count >= limit || (c.alloc < minShow && e.n != root) {
				break
			}
			o := out(c)
			e.out.Children = append(e.out.Children, o)
			shown++
			count++
			if len(c.children) > 0 {
				heap.Push(h, expansion{c, o})
			}
		}
		summarize(e, kids[shown:])
	}
	return top
}

func topFiles(all []fileRec, n int, z *sanitizer, paths map[int]string) []scan.SpaceFile {
	// A parità di spazio vale il percorso in ordine alfabetico: tra due nomi
	// dello stesso file resta quello scelto da dedupeLinks.
	real := make([]string, len(all))
	for i, f := range all {
		real[i] = join(fullPath(f.n), f.name)
	}
	idx := make([]int, len(all))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool {
		i, j := idx[a], idx[b]
		if all[i].alloc != all[j].alloc {
			return all[i].alloc > all[j].alloc
		}
		return strings.ToLower(real[i]) < strings.ToLower(real[j])
	})
	seen := map[uint64]bool{}
	var out []scan.SpaceFile
	for _, i := range idx {
		f := all[i]
		if len(out) == n {
			break
		}
		if f.id != 0 {
			if seen[f.id] {
				continue
			}
			seen[f.id] = true
		}
		id := len(out) + 1
		paths[id] = real[i]
		sf := scan.SpaceFile{ID: id, Path: z.path(real[i]), Alloc: f.alloc, Size: f.size, Cloud: f.cloud}
		if f.mod > 0 {
			sf.Modified = time.Unix(f.mod, 0).UTC().Format(time.RFC3339)
		}
		out = append(out, sf)
	}
	return out
}

func typeStats(exts map[string]*typeAcc) (types, cats []scan.SpaceType) {
	byCat := map[string]*typeAcc{}
	for ext, t := range exts {
		if t.files <= 0 {
			continue
		}
		types = append(types, scan.SpaceType{ID: ext, Alloc: t.alloc, Files: t.files})
		c := categoryOf(ext)
		ct := byCat[c]
		if ct == nil {
			ct = &typeAcc{}
			byCat[c] = ct
		}
		ct.alloc += t.alloc
		ct.files += t.files
	}
	order := func(s []scan.SpaceType) {
		sort.Slice(s, func(i, j int) bool {
			if s[i].Alloc != s[j].Alloc {
				return s[i].Alloc > s[j].Alloc
			}
			return s[i].ID < s[j].ID
		})
	}
	order(types)
	if len(types) > 30 {
		types = types[:30]
	}
	for c, t := range byCat {
		cats = append(cats, scan.SpaceType{ID: c, Alloc: t.alloc, Files: t.files})
	}
	order(cats)
	return types, cats
}
