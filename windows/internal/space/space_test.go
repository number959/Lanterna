package space

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"lanterna/internal/scan"
)

const (
	kb = int64(1) << 10
	mb = int64(1) << 20
	gb = int64(1) << 30
)

// fakeFS è un file system in memoria: percorso in minuscolo → voci.
type fakeFS struct {
	dirs   map[string][]entry
	denied map[string]bool
}

func (f *fakeFS) List(path string) ([]entry, error) {
	l := strings.ToLower(path)
	if f.denied[l] {
		return nil, errors.New("accesso negato")
	}
	e, found := f.dirs[l]
	if !found {
		return nil, fmt.Errorf("cartella inesistente: %s", path)
	}
	return e, nil
}

func dir(name string) entry { return entry{Name: name, Dir: true, Attrs: 0x10} }
func file(name string, alloc int64, id uint64) entry {
	return entry{Name: name, Alloc: alloc, Size: alloc - 100, ID: id, Mod: 1_790_000_000}
}

func sample() *fakeFS {
	cloud := entry{Name: "Contratto.pdf", Alloc: 0, Size: 10 * mb, Attrs: attrRecallOnDataAccess, ID: 900}
	junction := entry{Name: "Collegamento", Dir: true, Attrs: 0x10 | attrReparse, Tag: 0xA0000003}
	oneDrive := entry{Name: "OneDrive", Dir: true, Attrs: 0x10 | attrReparse, Tag: 0x9000601A}
	return &fakeFS{
		dirs: map[string][]entry{
			`c:\`:                                        {file("pagefile.sys", 4*gb, 1), file("hiberfil.sys", 3*gb, 2), dir("Windows"), dir("Users"), dir("$Recycle.Bin"), dir("Windows.old"), dir("Segreta"), dir("Vuota")},
			`c:\windows`:                                 {dir("System32"), dir("WinSxS"), dir("Temp"), file("MEMORY.DMP", 800*mb, 3)},
			`c:\windows\system32`:                        {file("kernel32.dll", 1*mb, 100), file("big.dll", 10*mb, 101)},
			`c:\windows\winsxs`:                          {dir("amd64_x")},
			`c:\windows\winsxs\amd64_x`:                  {file("kernel32.dll", 1*mb, 100), file("big.dll", 10*mb, 101), file("only.dll", 2*mb, 102)},
			`c:\windows\temp`:                            {file("x.tmp", 5*mb, 4)},
			`c:\users`:                                   {dir("mario"), dir("luca"), dir("Public")},
			`c:\users\mario`:                             {dir("Downloads"), dir("AppData"), oneDrive, junction},
			`c:\users\mario\downloads`:                   {file("film.mp4", 2*gb, 10), file("Mario_cv.docx", 64*kb, 11)},
			`c:\users\mario\appdata`:                     {dir("Local")},
			`c:\users\mario\appdata\local`:               {dir("Temp"), dir("Google")},
			`c:\users\mario\appdata\local\temp`:          {file("t.tmp", 100*mb, 12)},
			`c:\users\mario\appdata\local\google`:        {dir("Chrome")},
			`c:\users\mario\appdata\local\google\chrome`: {dir("User Data")},
			`c:\users\mario\appdata\local\google\chrome\user data`:                 {dir("Default"), dir("Profile 1")},
			`c:\users\mario\appdata\local\google\chrome\user data\default`:         {dir("Cache")},
			`c:\users\mario\appdata\local\google\chrome\user data\default\cache`:   {file("data_1", 50*mb, 13)},
			`c:\users\mario\appdata\local\google\chrome\user data\profile 1`:       {dir("Cache")},
			`c:\users\mario\appdata\local\google\chrome\user data\profile 1\cache`: {file("data_1", 30*mb, 14)},
			`c:\users\mario\onedrive`:    {cloud, file("Foto.jpg", 3*mb, 15)},
			`c:\users\luca`:              {file("vacanza.jpg", 1*gb, 16)},
			`c:\users\public`:            {},
			`c:\$recycle.bin`:            {dir("S-1-5-21-1")},
			`c:\$recycle.bin\s-1-5-21-1`: {file("$RAB12.zip", 500*mb, 17)},
			`c:\windows.old`:             {file("install.wim", 20*gb, 18)},
			`c:\vuota`:                   {},
		},
		denied: map[string]bool{`c:\segreta`: true},
	}
}

var env = Env{
	SystemRoot:    `C:\Windows`,
	Temp:          `C:\Users\mario\AppData\Local\Temp`,
	LocalAppData:  `C:\Users\mario\AppData\Local`,
	ProgramData:   `C:\ProgramData`,
	UserProfile:   `C:\Users\mario`,
	OneDrive:      `C:\Users\mario\OneDrive`,
	Username:      "mario",
	ProfilesDir:   `C:\Users`,
	OtherProfiles: []string{"luca"},
}

var vol = Volume{Drive: "C:", FS: "NTFS", TotalBytes: 100 * gb, FreeBytes: 60 * gb}

func run(t *testing.T, fs lister, workers int) *Result {
	t.Helper()
	res, err := scanWith(context.Background(), fs, `C:\`, vol, env, Options{Workers: workers, Now: func() time.Time { return time.Unix(1_800_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func find(n *scan.SpaceNode, path string) *scan.SpaceNode {
	if n == nil {
		return nil
	}
	if n.Path == path {
		return n
	}
	for _, c := range n.Children {
		if f := find(c, path); f != nil {
			return f
		}
	}
	return nil
}

func hint(r scan.SpaceReport, id string) *scan.SpaceHint {
	for i := range r.Hints {
		if r.Hints[i].ID == id {
			return &r.Hints[i]
		}
	}
	return nil
}

func TestScan(t *testing.T) {
	res := run(t, sample(), 4)
	r := res.Report
	// Collegamenti fisici: kernel32.dll e big.dll contati una volta, in
	// System32 (il percorso che viene prima in ordine alfabetico).
	if r.LinkedBytes != 11*mb {
		t.Errorf("collegamenti fisici: %d", r.LinkedBytes)
	}
	// Le cartelle piccole rispetto al disco si riassumono: per vederle si
	// analizza la sola cartella di Windows.
	win, err := scanWith(context.Background(), sample(), `C:\Windows`, vol, env, Options{Workers: 3})
	if err != nil {
		t.Fatal(err)
	}
	sys32, sxs := find(win.Report.Tree, `C:\Windows\System32`), find(win.Report.Tree, `C:\Windows\WinSxS`)
	if sys32 == nil || sxs == nil || sys32.Alloc != 11*mb || sxs.Alloc != 2*mb || sxs.Files != 1 || win.Report.LinkedBytes != 11*mb {
		t.Fatalf("System32 %+v, WinSxS %+v", sys32, sxs)
	}
	if win.Report.Tree.Name != `C:\Windows` || win.Report.Hints[0].ID != "crash-dumps" {
		t.Errorf("analisi della cartella di Windows: %q %+v", win.Report.Tree.Name, win.Report.Hints)
	}
	// Totale: tutti i file una volta, la giunzione non seguita, il file solo
	// online a zero.
	want := 4*gb + 3*gb + 800*mb + 11*mb + 2*mb + 5*mb + 2*gb + 64*kb + 100*mb + 50*mb + 30*mb + 3*mb + 1*gb + 500*mb + 20*gb
	if r.AllocBytes != want {
		t.Errorf("totale %d, atteso %d", r.AllocBytes, want)
	}
	if r.Files != 17 {
		t.Errorf("file: %d", r.Files)
	}
	if r.CloudFiles != 1 || r.CloudBytes != 10*mb {
		t.Errorf("solo online: %d file, %d byte", r.CloudFiles, r.CloudBytes)
	}
	if r.Denied != 1 || len(r.DeniedPaths) != 1 || r.DeniedPaths[0] != `C:\Segreta` {
		t.Errorf("cartelle non leggibili: %d %v", r.Denied, r.DeniedPaths)
	}
	if seg := find(r.Tree, `C:\Segreta`); seg == nil || !seg.Denied {
		t.Errorf("cartella negata nell'albero: %+v", seg)
	}
	// Nomi utente tolti dai percorsi e dai nomi delle cartelle.
	if n := find(r.Tree, `%USERPROFILE%`); n == nil || n.Name != "%USERPROFILE%" {
		t.Errorf("profilo dell'utente: %+v", n)
	}
	if n := find(r.Tree, `C:\Users\‹utente 1›`); n == nil || n.Name != "‹utente 1›" || n.Alloc != 1*gb {
		t.Errorf("altro profilo: %+v", n)
	}
	js, _ := json.Marshal(r)
	for _, leak := range []string{"mario", "luca", "Mario"} {
		if strings.Contains(string(js), leak) {
			t.Errorf("il rapporto contiene %q", leak)
		}
	}
	// I file più grandi, senza doppioni dei collegamenti fisici.
	if len(r.TopFiles) == 0 || r.TopFiles[0].Path != `C:\Windows.old\install.wim` || r.TopFiles[0].ID != 1 {
		t.Fatalf("file più grandi: %+v", r.TopFiles[:min(3, len(r.TopFiles))])
	}
	big := 0
	for _, f := range r.TopFiles {
		if strings.HasSuffix(f.Path, `big.dll`) {
			big++
		}
		if f.Path == `%USERPROFILE%\OneDrive\Contratto.pdf` && (!f.Cloud || f.Alloc != 0) {
			t.Errorf("file solo online: %+v", f)
		}
	}
	if big != 1 {
		t.Errorf("big.dll compare %d volte", big)
	}
	if res.FilePaths[1] != `C:\Windows.old\install.wim` {
		t.Errorf("percorso vero del file 1: %q", res.FilePaths[1])
	}
	if !strings.Contains(res.NodePaths[find(r.Tree, `%USERPROFILE%`).ID], "mario") {
		t.Error("il percorso vero resta nell'agente per aprire la cartella")
	}
	// Tipi e categorie.
	if r.Types[0].ID != ".wim" {
		t.Errorf("tipo più grande: %+v", r.Types[0])
	}
	cats := map[string]int64{}
	for _, c := range r.Categories {
		cats[c.ID] = c.Alloc
	}
	if cats["video"] != 2*gb || cats["archive"] != 20*gb+500*mb || cats["program"] != 13*mb || cats["system"] != 7*gb+800*mb {
		t.Errorf("categorie: %v", cats)
	}
	// Cartelle e file noti.
	for id, alloc := range map[string]int64{
		"windows-old": 20 * gb, "pagefile": 4 * gb, "hibernation": 3 * gb, "downloads": 2*gb + 64*kb, "crash-dumps": 800 * mb,
		"recycle-bin": 500 * mb, "temp-user": 100 * mb, "browser-cache": 80 * mb, "temp-windows": 5 * mb, "winsxs": 2 * mb, "onedrive": 3 * mb,
	} {
		h := hint(r, id)
		if h == nil || h.Alloc != alloc {
			t.Errorf("%s: %+v (atteso %d)", id, h, alloc)
		}
	}
	// Due profili di Chrome: due cartelle, quindi nessun percorso unico da mostrare.
	if h := hint(r, "browser-cache"); h.Path != "" || h.NodeID != 0 {
		t.Errorf("cache dei browser: %+v", h)
	}
	if h := hint(r, "windows-old"); h.Path != `C:\Windows.old` || h.NodeID == 0 || res.NodePaths[h.NodeID] != `C:\Windows.old` {
		t.Errorf("Windows.old: %+v", h)
	}
	if hint(r, "update-cache") != nil || hint(r, "virtual-disks") != nil {
		t.Error("cartelle note assenti non devono comparire")
	}
	if r.Hints[0].ID != "windows-old" {
		t.Errorf("le cartelle note vanno in ordine di spazio: %s", r.Hints[0].ID)
	}
	// Tutte le cartelle della radice compaiono, anche quelle vuote.
	if len(r.Tree.Children) != 6 || r.Tree.Children[0].Name != "Windows.old" {
		t.Errorf("radice: %d cartelle, prima %q", len(r.Tree.Children), r.Tree.Children[0].Name)
	}
	if r.Root != `C:\` || r.Drive != "C:" || r.TotalBytes != 100*gb || r.StartedAt != "2027-01-15T08:00:00Z" {
		t.Errorf("intestazione: %+v", r)
	}
}

func TestScanDeterministic(t *testing.T) {
	a, _ := json.Marshal(run(t, sample(), 1).Report)
	for w := 2; w <= 16; w *= 2 {
		b, _ := json.Marshal(run(t, sample(), w).Report)
		if string(a) != string(b) {
			t.Fatalf("con %d lettori il rapporto cambia", w)
		}
	}
}

// big costruisce un albero con molte cartelle per provare il parallelismo e
// il taglio dell'albero.
func big(depth, width int) *fakeFS {
	fs := &fakeFS{dirs: map[string][]entry{}, denied: map[string]bool{}}
	var mk func(path string, d int)
	n := uint64(1)
	mk = func(path string, d int) {
		var ents []entry
		for i := range width {
			n++
			ents = append(ents, file(fmt.Sprintf("f%d.bin", i), int64(i+1)*mb, n))
			if d < depth {
				name := fmt.Sprintf("d%d", i)
				ents = append(ents, dir(name))
				mk(join(path, name), d+1)
			}
		}
		fs.dirs[strings.ToLower(path)] = ents
	}
	mk(`C:\`, 0)
	return fs
}

func TestScanLarge(t *testing.T) {
	fs := big(4, 6) // 1 + 6 + 36 + 216 + 1296 = 1555 cartelle
	res, err := scanWith(context.Background(), fs, `C:\`, vol, env, Options{Workers: 8, TreeNodes: 200})
	if err != nil {
		t.Fatal(err)
	}
	r := res.Report
	if r.Dirs != 1554 || r.Files != 1555*6 {
		t.Fatalf("cartelle %d, file %d", r.Dirs, r.Files)
	}
	count := 0
	var walk func(n *scan.SpaceNode)
	var sumOK = true
	walk = func(n *scan.SpaceNode) {
		count++
		var sum int64
		for _, c := range n.Children {
			sum += c.Alloc
			walk(c)
		}
		if n.More != nil {
			sum += n.More.Alloc
		}
		if sum+n.OwnAlloc != n.Alloc {
			sumOK = false
		}
	}
	walk(r.Tree)
	if count > 200 || count < 150 {
		t.Errorf("cartelle nell'albero: %d", count)
	}
	if !sumOK {
		t.Error("figli mostrati + riassunto + file propri devono dare il totale di ogni cartella")
	}
	if len(res.NodePaths) != count {
		t.Errorf("percorsi veri: %d per %d cartelle", len(res.NodePaths), count)
	}
}

func TestScanCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := scanWith(ctx, big(3, 5), `C:\`, vol, env, Options{Workers: 4})
	if !errors.Is(err, context.Canceled) || res == nil || !res.Report.Partial {
		t.Fatalf("interruzione: %v %+v", err, res)
	}
}

func TestProgress(t *testing.T) {
	slow := &slowFS{fakeFS: big(2, 4)}
	var got []Progress
	_, err := scanWith(context.Background(), slow, `C:\`, vol, env, Options{Workers: 2, Progress: func(p Progress) { got = append(got, p) }})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[len(got)-1].Dirs == 0 {
		t.Fatalf("avanzamento: %+v", got)
	}
}

type slowFS struct{ *fakeFS }

func (s *slowFS) List(path string) ([]entry, error) {
	time.Sleep(15 * time.Millisecond)
	return s.fakeFS.List(path)
}

func TestHelpers(t *testing.T) {
	for in, want := range map[string]string{"film.MP4": ".mp4", ".gitignore": "", "archivio.tar.gz": ".gz", "senza": "", "x.": "", "nome con.spazio vero": "", "a.verylongextension": ""} {
		if got := extOf(in); got != want {
			t.Errorf("extOf(%q) = %q, atteso %q", in, got, want)
		}
	}
	if join(`C:\`, "x") != `C:\x` || join(`C:\a`, "x") != `C:\a\x` {
		t.Error("join")
	}
	if !under(`C:\Windows\Temp`, `c:\windows`) || under(`C:\WindowsApps`, `C:\Windows`) || !under(`C:\x`, `C:\`) {
		t.Error("under")
	}
	// Collegamenti simbolici e giunzioni no, cartelle di OneDrive sì.
	if follow(entry{Dir: true, Attrs: attrReparse, Tag: 0xA000000C}) || !follow(entry{Dir: true, Attrs: attrReparse, Tag: 0x9000601A}) || follow(entry{}) {
		t.Error("follow")
	}
	z := newSanitizer(Env{UserProfile: `C:\Users\Mario`, ProfilesDir: `C:\Users`, Username: "Mario", OtherProfiles: []string{"zeno", "Anna", "zeno"}})
	for in, want := range map[string]string{
		`C:\Users\mario\Documenti`: `%USERPROFILE%\Documenti`,
		`C:\Users\Anna`:            `C:\Users\‹utente 1›`,
		`C:\Users\ZENO\x`:          `C:\Users\‹utente 2›\x`,
		`D:\Backup\Mario\foto`:     `D:\Backup\%USERNAME%\foto`,
		`D:\Mario_cv.docx`:         `D:\%USERNAME%_cv.docx`,
		`D:\Marion.txt`:            `D:\Marion.txt`,
		`D:\foto di anna 2024.jpg`: `D:\foto di ‹utente 1› 2024.jpg`,
		`C:\Users\Public`:          `C:\Users\Public`,
		`C:\Windows`:               `C:\Windows`,
	} {
		if got := z.path(in); got != want {
			t.Errorf("path(%q) = %q, atteso %q", in, got, want)
		}
	}
}

// dirInfo costruisce una voce FILE_ID_BOTH_DIR_INFO come la restituisce
// Windows (allineata a 8 byte).
func dirInfo(name string, attrs uint32, size, alloc int64, ea uint32, id uint64, filetime uint64) []byte {
	u := utf16.Encode([]rune(name))
	n := offName + 2*len(u)
	n = (n + 7) &^ 7
	b := make([]byte, n)
	le := binary.LittleEndian
	le.PutUint64(b[offLastWrite:], filetime)
	le.PutUint64(b[offEndOfFile:], uint64(size))
	le.PutUint64(b[offAlloc:], uint64(alloc))
	le.PutUint32(b[offAttrs:], attrs)
	le.PutUint32(b[offNameLen:], uint32(2*len(u)))
	le.PutUint32(b[offEaSize:], ea)
	le.PutUint64(b[offFileID:], id)
	for i, c := range u {
		le.PutUint16(b[offName+2*i:], c)
	}
	return b
}

func TestParseDirInfo(t *testing.T) {
	var buf []byte
	parts := [][]byte{
		dirInfo(".", 0x10, 0, 0, 0, 1, 0),
		dirInfo("..", 0x10, 0, 0, 0, 2, 0),
		dirInfo("Fotografie è più bella", 0x10, 0, 0, 0, 3, 0),
		dirInfo("film.mp4", 0x20, 1_500_000_123, 1_500_004_352, 0, 0x0005000000001234, 133_000_000_000_000_000),
		dirInfo("Collegamento", 0x10|attrReparse, 0, 0, 0xA0000003, 5, 0),
		dirInfo("Contratto.pdf", 0x20|attrRecallOnDataAccess, 10_000, 0, 0, 6, 0),
		dirInfo("senza-numero.bin", 0x20, 10, 4096, 0, ^uint64(0), 0),
	}
	le := binary.LittleEndian
	for i, p := range parts {
		if i < len(parts)-1 {
			le.PutUint32(p[offNext:], uint32(len(p)))
		}
		buf = append(buf, p...)
	}
	buf = append(buf, make([]byte, 64)...) // resto del buffer non usato
	got := parseDirInfo(buf, nil)
	if len(got) != 5 {
		t.Fatalf("voci: %+v", got)
	}
	if got[4].ID != 0 {
		t.Errorf("numero non univoco: %+v", got[4])
	}
	if got[0].Name != "Fotografie è più bella" || !got[0].Dir || !follow(got[0]) {
		t.Errorf("cartella: %+v", got[0])
	}
	f := got[1]
	if f.Name != "film.mp4" || f.Dir || f.Size != 1_500_000_123 || f.Alloc != 1_500_004_352 || f.ID != 0x0005000000001234 || f.Mod != 1_655_526_400 {
		t.Errorf("file: %+v", f)
	}
	if got[2].Tag != 0xA0000003 || follow(got[2]) {
		t.Errorf("giunzione: %+v", got[2])
	}
	if !cloudOnly(got[3]) || got[3].Alloc != 0 {
		t.Errorf("file solo online: %+v", got[3])
	}
	// Buffer troncato a metà nome: si ferma senza panico.
	if n := len(parseDirInfo(buf[:offName+3], nil)); n != 0 {
		t.Errorf("buffer troncato: %d voci", n)
	}
}

func TestLabels(t *testing.T) {
	ids := []string{"virtual-disks"}
	for _, h := range hintSpecs {
		ids = append(ids, h.id)
	}
	for _, id := range ids {
		if HintLabels[id] == "" {
			t.Errorf("consiglio senza nome: %s", id)
		}
	}
	if len(HintLabels) != len(ids) {
		t.Errorf("nomi in più: %d contro %d", len(HintLabels), len(ids))
	}
	cats := map[string]bool{"system": true, "other": true}
	for _, c := range categories {
		cats[c] = true
	}
	for c := range cats {
		if CategoryLabels[c] == "" {
			t.Errorf("categoria senza nome: %s", c)
		}
	}
	if len(CategoryLabels) != len(cats) {
		t.Errorf("categorie in più: %d contro %d", len(CategoryLabels), len(cats))
	}
}
