package space

import (
	"sort"
	"strings"

	"lanterna/internal/scan"
)

// hintSpec è una cartella o un file noto. I percorsi possono contenere "*"
// al posto di una cartella (per esempio i profili dei browser); significato
// e consigli li dà l'interfaccia, che conosce gli identificativi.
type hintSpec struct {
	id    string
	paths func(env Env, drive string) []string
	// files: nomi di file noti (nella radice dell'unità o nella cartella di
	// Windows) invece di cartelle.
	files func(env Env, drive string) []string
}

func p(parts ...string) string {
	out := parts[0]
	for _, x := range parts[1:] {
		out = join(out, x)
	}
	return out
}

// nonEmpty esclude i percorsi che non si possono costruire (variabile
// d'ambiente mancante).
func nonEmpty(base string, rest ...string) []string {
	if base == "" {
		return nil
	}
	return []string{p(append([]string{base}, rest...)...)}
}

var hintSpecs = []hintSpec{
	{id: "temp-user", paths: func(e Env, _ string) []string { return nonEmpty(e.Temp) }},
	{id: "temp-windows", paths: func(e Env, _ string) []string { return nonEmpty(e.SystemRoot, "Temp") }},
	{id: "update-cache", paths: func(e Env, _ string) []string { return nonEmpty(e.SystemRoot, "SoftwareDistribution", "Download") }},
	{id: "delivery-optimization", paths: func(e Env, _ string) []string {
		return nonEmpty(e.SystemRoot, "ServiceProfiles", "NetworkService", "AppData", "Local", "Microsoft", "Windows", "DeliveryOptimization")
	}},
	{id: "windows-old", paths: func(_ Env, d string) []string { return []string{d + `\Windows.old`} }},
	{id: "upgrade-files", paths: func(_ Env, d string) []string { return []string{d + `\$WINDOWS.~BT`, d + `\$Windows.~WS`} }},
	{id: "recycle-bin", paths: func(_ Env, d string) []string { return []string{d + `\$Recycle.Bin`} }},
	{id: "winsxs", paths: func(e Env, _ string) []string { return nonEmpty(e.SystemRoot, "WinSxS") }},
	{id: "installer", paths: func(e Env, _ string) []string { return nonEmpty(e.SystemRoot, "Installer") }},
	{id: "error-reports", paths: func(e Env, _ string) []string { return nonEmpty(e.ProgramData, "Microsoft", "Windows", "WER") }},
	{id: "crash-dumps",
		paths: func(e Env, _ string) []string {
			return append(append(nonEmpty(e.LocalAppData, "CrashDumps"), nonEmpty(e.SystemRoot, "Minidump")...), nonEmpty(e.SystemRoot, "LiveKernelReports")...)
		},
		files: func(e Env, _ string) []string { return nonEmpty(e.SystemRoot, "MEMORY.DMP") }},
	{id: "browser-cache", paths: func(e Env, _ string) []string {
		if e.LocalAppData == "" {
			return nil
		}
		l := e.LocalAppData
		return []string{
			p(l, "Microsoft", "Edge", "User Data", "*", "Cache"),
			p(l, "Microsoft", "Edge", "User Data", "*", "Code Cache"),
			p(l, "Google", "Chrome", "User Data", "*", "Cache"),
			p(l, "Google", "Chrome", "User Data", "*", "Code Cache"),
			p(l, "Mozilla", "Firefox", "Profiles", "*", "cache2"),
		}
	}},
	{id: "package-cache", paths: func(e Env, _ string) []string { return nonEmpty(e.ProgramData, "Package Cache") }},
	{id: "downloads", paths: func(e Env, _ string) []string { return nonEmpty(e.UserProfile, "Downloads") }},
	{id: "onedrive", paths: func(e Env, _ string) []string { return nonEmpty(e.OneDrive) }},
	{id: "hibernation", files: func(_ Env, d string) []string { return []string{d + `\hiberfil.sys`} }},
	{id: "pagefile", files: func(_ Env, d string) []string { return []string{d + `\pagefile.sys`, d + `\swapfile.sys`} }},
}

// virtualDisks sono le estensioni dei dischi virtuali (WSL, Docker, Hyper-V,
// VirtualBox, VMware), che non si rimpiccioliscono da soli.
var virtualDisks = []string{".vhdx", ".vhd", ".avhdx", ".vmdk", ".vdi", ".qcow2"}

// findNodes trova le cartelle di un percorso, con "*" per qualunque
// cartella, a partire dalla radice analizzata.
func findNodes(root *node, rootPath, pattern string) []*node {
	if !under(pattern, rootPath) {
		return nil
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(pattern), strings.TrimSuffix(strings.ToLower(rootPath), `\`)), `\`)
	cur := []*node{root}
	if rest == "" {
		return cur
	}
	for _, part := range strings.Split(rest, `\`) {
		var next []*node
		for _, n := range cur {
			for _, c := range n.children {
				if part == "*" || strings.ToLower(c.name) == part {
					next = append(next, c)
				}
			}
		}
		if len(next) == 0 {
			return nil
		}
		cur = next
	}
	return cur
}

func hints(root *node, known []fileRec, exts map[string]*typeAcc, rootPath string, env Env, z *sanitizer, ids map[*node]int) []scan.SpaceHint {
	drive := strings.TrimSuffix(rootPath, `\`)
	if len(drive) > 2 {
		drive = drive[:2]
	}
	var out []scan.SpaceHint
	for _, h := range hintSpecs {
		var hint scan.SpaceHint
		var paths []string
		if h.paths != nil {
			var nodes []*node
			for _, pat := range h.paths(env, drive) {
				found := findNodes(root, rootPath, pat)
				if len(found) > 0 {
					paths = append(paths, pat)
				}
				nodes = append(nodes, found...)
			}
			for _, n := range nodes {
				hint.Alloc += n.alloc
				hint.Files += n.files
			}
			if len(nodes) == 1 {
				hint.NodeID = ids[nodes[0]]
			}
		}
		if h.files != nil {
			for _, f := range h.files(env, drive) {
				lf := strings.ToLower(f)
				for _, k := range known {
					if strings.ToLower(join(fullPath(k.n), k.name)) == lf {
						hint.Alloc += k.alloc
						hint.Files++
						paths = append(paths, f)
					}
				}
			}
		}
		if hint.Alloc <= 0 {
			continue
		}
		hint.ID = h.id
		if len(paths) == 1 {
			hint.Path = z.path(paths[0])
		}
		out = append(out, hint)
	}
	var vd scan.SpaceHint
	for _, e := range virtualDisks {
		if t := exts[e]; t != nil {
			vd.Alloc += t.alloc
			vd.Files += t.files
		}
	}
	if vd.Alloc > 0 {
		vd.ID = "virtual-disks"
		out = append(out, vd)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Alloc > out[j].Alloc })
	return out
}

// sanitizer toglie i nomi utente dai percorsi: il profilo di chi usa Polaris
// diventa %USERPROFILE%, gli altri profili ‹utente 1›, ‹utente 2›... (in
// ordine alfabetico), e il nome utente altrove %USERNAME%.
type sanitizer struct {
	profile     string
	profilesDir string
	others      map[string]string
	otherNames  []string // chiavi di others in ordine, per un risultato stabile
	user        string
}

func newSanitizer(env Env) *sanitizer {
	z := &sanitizer{
		profile:     strings.TrimSuffix(strings.ToLower(env.UserProfile), `\`),
		profilesDir: strings.TrimSuffix(strings.ToLower(env.ProfilesDir), `\`),
		others:      map[string]string{},
		user:        strings.ToLower(env.Username),
	}
	names := append([]string(nil), env.OtherProfiles...)
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	n := 0
	for _, name := range names {
		l := strings.ToLower(name)
		if _, dup := z.others[l]; dup || l == "" {
			continue
		}
		n++
		z.others[l] = "‹utente " + itoa(n) + "›"
		z.otherNames = append(z.otherNames, l)
	}
	return z
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// maskWord sostituisce name in s quando è una parola a sé (non parte di una
// parola più lunga), senza badare alle maiuscole: "Mario_cv.docx" diventa
// "%USERNAME%_cv.docx", "Marion.txt" resta com'è.
func maskWord(s, name, with string) string {
	if len(name) < 3 {
		return s
	}
	ls, ln := strings.ToLower(s), strings.ToLower(name)
	letter := func(i int) bool {
		if i < 0 || i >= len(s) {
			return false
		}
		c := s[i]
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c >= 0x80
	}
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(ls[i:], ln)
		if j < 0 {
			b.WriteString(s[i:])
			return b.String()
		}
		j += i
		if !letter(j-1) && !letter(j+len(ln)) {
			b.WriteString(s[i:j])
			b.WriteString(with)
		} else {
			b.WriteString(s[i : j+len(ln)])
		}
		i = j + len(ln)
	}
}

func (z *sanitizer) path(path string) string {
	lp := strings.ToLower(path)
	out := path
	switch {
	case z.profile != "" && (lp == z.profile || strings.HasPrefix(lp, z.profile+`\`)):
		out = "%USERPROFILE%" + path[len(z.profile):]
	case z.profilesDir != "" && strings.HasPrefix(lp, z.profilesDir+`\`):
		rest := path[len(z.profilesDir)+1:]
		name, tail, more := strings.Cut(rest, `\`)
		if alias, found := z.others[strings.ToLower(name)]; found {
			out = path[:len(z.profilesDir)+1] + alias
			if more {
				out += `\` + tail
			}
		}
	}
	// Il nome dell'utente, e quelli degli altri profili, anche dentro i nomi
	// di file e cartelle.
	parts := strings.Split(out, `\`)
	for i, part := range parts {
		if z.user != "" {
			part = maskWord(part, z.user, "%USERNAME%")
		}
		for _, name := range z.otherNames {
			part = maskWord(part, name, z.others[name])
		}
		parts[i] = part
	}
	return strings.Join(parts, `\`)
}
