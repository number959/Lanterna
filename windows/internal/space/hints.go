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
	// systemOnly: solo sull'unità di Windows.
	systemOnly bool
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
	{id: "windows-old", systemOnly: true, paths: func(_ Env, d string) []string { return []string{d + `\Windows.old`} }},
	{id: "upgrade-files", systemOnly: true, paths: func(_ Env, d string) []string { return []string{d + `\$WINDOWS.~BT`, d + `\$Windows.~WS`} }},
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

func isVirtualDisk(ext string) bool {
	for _, e := range virtualDisks {
		if ext == e {
			return true
		}
	}
	return false
}

// baseName è l'ultima parte di un percorso di Windows ("C:\Users" -> "Users"),
// uguale su ogni sistema (filepath.Base usa "/" fuori da Windows).
func baseName(p string) string {
	p = strings.TrimSuffix(p, `\`)
	if i := strings.LastIndexByte(p, '\\'); i >= 0 {
		return p[i+1:]
	}
	return p
}

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

func hints(root *node, known []fileRec, exts map[string]*typeAcc, imageBackups typeAcc, rootPath string, env Env, z *sanitizer, ids map[*node]int) []scan.SpaceHint {
	drive := strings.TrimSuffix(rootPath, `\`)
	if len(drive) > 2 {
		drive = drive[:2]
	}
	system := len(env.SystemRoot) >= 2 && strings.EqualFold(drive, env.SystemRoot[:2])
	var out []scan.SpaceHint
	for _, h := range hintSpecs {
		// Su un'altra unità Windows.old è una vecchia copia che Windows non
		// toglie da solo e che Impostazioni e Pulizia disco non vedono.
		if h.systemOnly && !system {
			continue
		}
		var hint scan.SpaceHint
		var paths []string
		if h.paths != nil {
			var nodes []*node
			for _, pat := range h.paths(env, drive) {
				found := findNodes(root, rootPath, pat)
				// Il percorso com'è scritto sul disco, non come nella
				// variabile d'ambiente ("C:\windows\WinSxS").
				for _, n := range found {
					paths = append(paths, fullPath(n))
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
	// I backup d'immagine di sistema (WindowsImageBackup) sono dischi
	// virtuali da non compattare: restano fuori.
	vd := scan.SpaceHint{Alloc: -imageBackups.alloc, Files: -imageBackups.files}
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
