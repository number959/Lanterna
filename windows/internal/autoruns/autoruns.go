// Package autoruns legge ciò che si avvia da solo sul computer, come
// Autoruns di Sysinternals: chiavi di avvio del registro e cartelle
// Esecuzione automatica, Winlogon, dirottamenti noti (IFEO, BootExecute,
// AppInit_DLLs), pacchetti LSA, monitor e processori di stampa, provider di
// rete, servizi e driver, attività pianificate, sottoscrizioni WMI
// permanenti ed estensioni dei browser. Produce scan.AutorunsData.
//
// Tutto in sola lettura: chiavi del registro aperte solo per leggere,
// Gestione servizi con i soli diritti di elenco e lettura, attività e WMI
// lette da uno script PowerShell che non chiama metodi che modificano, file
// dei browser aperti con la condivisione completa e chiusi subito. Polaris
// non disattiva né cancella nessuna voce.
//
// Come Autoruns con «Hide Windows Entries», le voci di Windows firmate da
// Microsoft si contano ma non si elencano (regola in windowsEntry).
package autoruns

import (
	"context"
	"sort"
	"strings"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/sign"
)

// Categories sono le categorie delle voci, nell'ordine in cui si elencano.
var Categories = []string{"logon", "winlogon", "hijacks", "services", "drivers", "tasks", "wmi", "browser", "lsa", "print", "network"}

func categoryIndex(c string) int {
	for i, x := range Categories {
		if x == c {
			return i
		}
	}
	return len(Categories)
}

// item è una voce letta, prima dei fatti sui file.
type item struct {
	entry scan.AutorunEntry
	// file e target sono i percorsi assoluti da verificare ("" se nessuno):
	// il file della voce e quello che un programma di sistema esegue per
	// suo conto.
	file, target string
	// unverified: il percorso dipende dal profilo dell'utente con cui gira
	// la voce, che non è chi usa Polaris; non si verifica (né «mancante» né
	// firma), si mostra soltanto.
	unverified bool
	// interpreted: programma di sistema che esegue un comando scritto negli
	// argomenti, senza un file da verificare (powershell -Command...).
	interpreted bool
	// hijack: dirottamento noto (Winlogon diverso dal predefinito, IFEO,
	// BootExecute non predefinito, AppInit attivo, percorso senza virgolette
	// con un file intercettore): si elenca sempre.
	hijack bool
	// component: parte interna del browser; si conta e non si elenca.
	component bool
	// always: si elenca anche se è di Windows (sottoscrizioni WMI permanenti,
	// controllo del disco programmato in BootExecute): il motore la giudica.
	always bool
	// others sono le altre azioni di un'attività pianificata, verificate come
	// la voce: se una non è di Windows si mostra quella (settle).
	others []item
}

// usable: il file esiste, è firmato da Microsoft per un componente suo e
// non sta in una cartella dove un utente senza privilegi può scrivere.
func usable(f *scan.FileFacts) bool {
	return f != nil && !f.Missing && sign.IsMicrosoft(f.Signature) && !sign.UserWritable(f.Folder)
}

// windowsEntry applica la regola «Hide Windows Entries» di Autoruns: una
// voce di Windows non si elenca (si conta in Counts[categoria].Microsoft) se
// il suo file c'è, è firmato da Microsoft, non sta in una cartella
// dell'utente e non esegue per conto suo un file che non sia di Microsoft.
// Si elenca sempre se il file manca o non si è potuto verificare, se non è
// firmata da Microsoft, se sta in una cartella dell'utente, se è un
// dirottamento, se un programma di sistema esegue un comando interpretato
// (anche quando non si sa quale file esegua) o se è una sottoscrizione WMI
// permanente (always: su Windows non ce ne sono da nascondere).
func windowsEntry(it item) bool {
	if it.hijack || it.interpreted || it.unverified || it.component || it.always {
		return false
	}
	if !usable(it.entry.File) {
		return false
	}
	return it.entry.Target == nil || usable(it.entry.Target)
}

// settle sceglie, per un'attività con più azioni, quella da mostrare dopo
// la verifica dei file: la prima che non sarebbe nascosta come voce di
// Windows. Se sono tutte di Windows resta la prima scelta.
func settle(it item) item {
	if len(it.others) == 0 || !windowsEntry(it) {
		it.others = nil
		return it
	}
	for _, a := range it.others {
		if !windowsEntry(a) {
			a.others = nil
			return a
		}
	}
	it.others = nil
	return it
}

// assemble conta le voci per categoria e tiene in Entries solo quelle da
// mostrare, nell'ordine delle categorie e poi di lettura.
func assemble(items []item) (entries []scan.AutorunEntry, counts map[string]scan.AutorunCount) {
	entries = []scan.AutorunEntry{}
	counts = map[string]scan.AutorunCount{}
	for _, it := range items {
		it = settle(it)
		c := counts[it.entry.Category]
		c.Total++
		switch {
		case it.component:
		case windowsEntry(it):
			c.Microsoft++
		default:
			entries = append(entries, it.entry)
		}
		counts[it.entry.Category] = c
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return categoryIndex(entries[i].Category) < categoryIndex(entries[j].Category)
	})
	return entries, counts
}

// source è una sorgente di voci (registro, servizi, attività...).
type source struct {
	name string
	read func(ctx context.Context) sourceResult
}

type sourceResult struct {
	items []item
	// denied: la categoria indicata è stata letta solo in parte o per
	// niente per i permessi.
	denied []string
	err    error
}

// factsFunc calcola i fatti su un file (sign.Checker.Facts).
type factsFunc func(ctx context.Context, path string) *scan.FileFacts

// rankFunc dà l'ordine di verifica di un file (più basso prima).
type rankFunc func(category, path string) int

// checkOrder è l'ordine in cui si verificano le firme, perché se il tempo
// scade restino senza verifica i file meno a rischio: prima quelli nelle
// cartelle che un utente può scrivere (sign.UserWritable, e con loro
// programData e le altre cartelle), poi Program Files, poi la cartella di
// Windows e per ultimi i driver di Windows, che sono molti.
func checkOrder(category, path, profile string) int {
	switch folder := sign.FolderOf(path, profile); {
	case sign.UserWritable(folder):
		return 0
	case folder == "programFiles":
		return 1
	case folder == "windows" && category == "drivers":
		return 3
	case folder == "windows":
		return 2
	}
	return 0
}

// dest è un posto in cui mettere i fatti su un file: la voce idx, la sua
// azione alt (0 la voce, k l'azione others[k-1]), il file o il target.
type dest struct {
	idx, alt int
	target   bool
}

type job struct {
	path string
	rank int
}

type jobResult struct {
	path  string
	facts *scan.FileFacts
}

// gather legge le sorgenti in parallelo e intanto calcola i fatti sui file
// delle voci già lette, con workers goroutine, nell'ordine di rank (nil:
// nell'ordine di arrivo) e una volta sola per percorso. Si ferma alla
// scadenza di ctx più grace (una chiamata di Windows bloccata non si
// interrompe): le voci rimaste senza verifica ricevono plain (il solo
// percorso) e partial vale true. Le voci si toccano solo da questa
// goroutine; i lavoratori ricevono copie dei percorsi.
func gather(ctx context.Context, sources []source, facts factsFunc, plain func(string) *scan.FileFacts, rank rankFunc, workers int, grace time.Duration) (items []item, denied []string, errs []error, partial bool) {
	if workers < 1 {
		workers = 1
	}
	stop := make(chan struct{})
	defer close(stop)
	results := make(chan sourceResult, len(sources))
	for _, s := range sources {
		go func(s source) {
			results <- s.read(ctx)
		}(s)
	}
	jobs := make(chan job)
	done := make(chan jobResult)
	for w := 0; w < workers; w++ {
		go func() {
			for {
				select {
				case j := <-jobs:
					r := jobResult{path: j.path, facts: facts(ctx, j.path)}
					select {
					case done <- r:
					case <-stop:
						return
					}
				case <-stop:
					return
				}
			}
		}()
	}
	// at restituisce l'azione indicata da d.
	at := func(d dest) *item {
		if d.alt > 0 {
			return &items[d.idx].others[d.alt-1]
		}
		return &items[d.idx]
	}
	set := func(d dest, f *scan.FileFacts) {
		c := *f
		if d.target {
			at(d).entry.Target = &c
		} else {
			at(d).entry.File = &c
		}
	}
	// wanted: i posti in attesa dei fatti su un percorso (accodato o in
	// corso); known: i fatti già arrivati; waiting conta i lavori accodati
	// o in corso, non ancora restituiti.
	var queue []job
	wanted := map[string][]dest{}
	known := map[string]*scan.FileFacts{}
	pending, waiting := len(sources), 0
	add := func(d dest, path, category string) {
		k := strings.ToLower(path)
		if f := known[k]; f != nil {
			set(d, f)
			return
		}
		if ds, ok := wanted[k]; ok {
			wanted[k] = append(ds, d)
			return
		}
		wanted[k] = []dest{d}
		j := job{path: path}
		if rank != nil {
			j.rank = rank(category, path)
		}
		queue = append(queue, j)
		waiting++
	}
	var expired <-chan time.Time
	ctxDone := ctx.Done()
	for pending > 0 || waiting > 0 {
		var send chan job
		var next job
		if len(queue) > 0 {
			send, next = jobs, queue[0]
		}
		select {
		case r := <-results:
			pending--
			base := len(items)
			items = append(items, r.items...)
			denied = append(denied, r.denied...)
			if r.err != nil {
				errs = append(errs, r.err)
			}
			for i := base; i < len(items); i++ {
				for alt := 0; alt <= len(items[i].others); alt++ {
					a := at(dest{idx: i, alt: alt})
					if a.unverified {
						continue
					}
					if a.file != "" {
						add(dest{idx: i, alt: alt}, a.file, a.entry.Category)
					}
					if a.target != "" {
						add(dest{idx: i, alt: alt, target: true}, a.target, a.entry.Category)
					}
				}
			}
			sort.SliceStable(queue, func(a, b int) bool { return queue[a].rank < queue[b].rank })
		case send <- next:
			queue = queue[1:]
		case r := <-done:
			waiting--
			k := strings.ToLower(r.path)
			ds := wanted[k]
			delete(wanted, k)
			if r.facts != nil {
				known[k] = r.facts
				for _, d := range ds {
					set(d, r.facts)
				}
			}
		case <-ctxDone:
			// Scaduto il tempo con letture o verifiche ancora in corso: quel
			// che arriva entro il margine entra, ma senza firma.
			partial = true
			ctxDone = nil
			expired = time.After(grace)
		case <-expired:
			pending, waiting = 0, 0
		}
	}
	// Le voci senza fatti (verifica non finita, file non verificabile):
	// solo il percorso.
	for i := range items {
		for alt := 0; alt <= len(items[i].others); alt++ {
			it := at(dest{idx: i, alt: alt})
			if it.file != "" && it.entry.File == nil {
				it.entry.File = plain(it.file)
			}
			if it.target != "" && it.entry.Target == nil {
				it.entry.Target = plain(it.target)
			}
		}
	}
	return items, denied, errs, partial
}

// plainFacts sono i fatti su un file non verificato: il percorso pulito e il
// tipo di cartella, che non si dice per un percorso con le variabili di un
// altro utente (%LOCALAPPDATA% di un'attività di SYSTEM non è il profilo di
// chi usa Polaris): l'interfaccia scrive allora «cartella non letta».
func plainFacts(p, profile string, clean func(string) string) *scan.FileFacts {
	folder := ""
	if !strings.Contains(p, "%") {
		folder = sign.FolderOf(p, profile)
	}
	return &scan.FileFacts{Path: clean(p), Folder: folder}
}

// onNetwork: un percorso su una condivisione di rete. Non si apre, né per
// sapere se esiste né per la firma: Windows si collegherebbe a un server
// scelto da chi ha scritto la voce, con le credenziali dell'utente, e
// leggerebbe tutto il file dalla rete.
func onNetwork(p, profile string) bool {
	return sign.FolderOf(p, profile) == "network"
}

// networkFacts sono i fatti su un file in rete, senza toccarlo: firma non
// verificabile, e non «mancante».
func networkFacts(p string, clean func(string) string) *scan.FileFacts {
	return &scan.FileFacts{Path: clean(p), Folder: "network", Signature: &scan.FileSignature{Status: "unknown"}}
}
