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
// dirottamento o se un programma di sistema esegue un comando interpretato.
func windowsEntry(it item) bool {
	if it.hijack || it.interpreted || it.unverified || it.component {
		return false
	}
	if !usable(it.entry.File) {
		return false
	}
	return it.entry.Target == nil || usable(it.entry.Target)
}

// assemble conta le voci per categoria e tiene in Entries solo quelle da
// mostrare, nell'ordine delle categorie e poi di lettura.
func assemble(items []item) (entries []scan.AutorunEntry, counts map[string]scan.AutorunCount) {
	entries = []scan.AutorunEntry{}
	counts = map[string]scan.AutorunCount{}
	for _, it := range items {
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

type job struct {
	idx    int
	target bool
	path   string
}

type jobResult struct {
	job
	facts *scan.FileFacts
}

// gather legge le sorgenti in parallelo e intanto calcola i fatti sui file
// delle voci già lette, con workers goroutine. Si ferma alla scadenza di ctx
// più grace (una chiamata di Windows bloccata non si interrompe): le voci
// rimaste senza verifica ricevono plain (il solo percorso) e partial vale
// true. Le voci si toccano solo da questa goroutine; i lavoratori ricevono
// copie dei percorsi.
func gather(ctx context.Context, sources []source, facts factsFunc, plain func(string) *scan.FileFacts, workers int, grace time.Duration) (items []item, denied []string, errs []error, partial bool) {
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
					r := jobResult{job: j, facts: facts(ctx, j.path)}
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
	// waiting conta i lavori accodati o in corso, non ancora restituiti.
	var queue []job
	pending, waiting := len(sources), 0
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
				if items[i].unverified {
					continue
				}
				if items[i].file != "" {
					queue = append(queue, job{idx: i, path: items[i].file})
					waiting++
				}
				if items[i].target != "" {
					queue = append(queue, job{idx: i, target: true, path: items[i].target})
					waiting++
				}
			}
		case send <- next:
			queue = queue[1:]
		case r := <-done:
			waiting--
			if r.target {
				items[r.idx].entry.Target = r.facts
			} else {
				items[r.idx].entry.File = r.facts
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
		it := &items[i]
		if it.file != "" && it.entry.File == nil {
			it.entry.File = plain(it.file)
		}
		if it.target != "" && it.entry.Target == nil {
			it.entry.Target = plain(it.target)
		}
	}
	return items, denied, errs, partial
}
