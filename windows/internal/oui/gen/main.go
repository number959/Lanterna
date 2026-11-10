//go:build ignore

// Genera oui.txt.gz, l'elenco dei produttori che il pacchetto oui incorpora,
// dall'elenco pubblico dei prefissi MAC della IEEE Registration Authority già
// scaricato in CSV. Lo avvia scripts/oui.sh, dalla cartella windows:
//
//	go run ./internal/oui/gen/main.go -data AAAA-MM-GG -out internal/oui/oui.txt.gz <cartella> <indirizzo>...
//
// Per ogni indirizzo legge dalla cartella il file con lo stesso nome (oui.csv,
// mam.csv, oui36.csv) con encoding/csv, perché i nomi contengono virgole tra
// virgolette, e di ogni riga tiene il registro (MA-L, MA-M, MA-S), il
// prefisso e il nome abbreviato con oui.Normalize. Scarta i blocchi senza un
// produttore: quelli "Private", quelli che la IEEE Registration Authority
// suddivide in MA-M e MA-S, e i prefissi elencati più volte con
// organizzazioni diverse. Scrive le righe "PREFISSO<TAB>Nome" in ordine,
// precedute da commenti con fonti, giorno del download e conteggi, in un gzip
// riproducibile (senza nome né data del file nell'intestazione: stessi dati,
// stessi byte).
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"lanterna/internal/oui"
)

// registry è un registro della IEEE, con la lunghezza del prefisso in cifre
// esadecimali.
type registry struct {
	name   string
	digits int
}

var registries = []registry{{"MA-L", 6}, {"MA-M", 7}, {"MA-S", 9}}

// list è l'elenco letto dai CSV.
type list struct {
	names   map[string][]string // prefisso -> nomi abbreviati distinti
	reg     map[string]int      // prefisso -> registro
	private int                 // blocchi "Private" o senza nome
	ieee    int                 // blocchi suddivisi dalla IEEE Registration Authority
}

func main() {
	date := flag.String("data", "", "giorno del download, AAAA-MM-GG (UTC)")
	out := flag.String("out", "oui.txt.gz", "file da scrivere")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "uso: go run gen/main.go -data AAAA-MM-GG -out oui.txt.gz <cartella con i CSV> <indirizzo>...")
	}
	flag.Parse()
	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*date, *out, flag.Arg(0), flag.Args()[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "oui:", err)
		os.Exit(1)
	}
}

func run(date, out, dir string, urls []string) error {
	if _, err := time.Parse(time.DateOnly, date); err != nil {
		return fmt.Errorf("giorno del download non valido (AAAA-MM-GG): %q", date)
	}
	l := &list{names: map[string][]string{}, reg: map[string]int{}}
	for _, u := range urls {
		if err := l.read(filepath.Join(dir, path.Base(u))); err != nil {
			return err
		}
	}

	// Righe in ordine di prefisso; un prefisso con più organizzazioni non dice
	// quale abbia fatto il dispositivo e resta fuori.
	var lines []string
	count := make([]int, len(registries))
	ambiguous := 0
	for p, names := range l.names {
		if len(names) > 1 {
			ambiguous++
			continue
		}
		lines = append(lines, p+"\t"+names[0])
		count[l.reg[p]]++
	}
	slices.Sort(lines)
	distinct := map[string]bool{}
	for _, line := range lines {
		_, name, _ := strings.Cut(line, "\t")
		distinct[name] = true
	}

	var head strings.Builder
	fmt.Fprintln(&head, "# Prefissi MAC dell'elenco pubblico della IEEE Registration Authority (MA-L, MA-M, MA-S)")
	for _, u := range urls {
		fmt.Fprintf(&head, "# fonte: %s\n", u)
	}
	fmt.Fprintf(&head, "# scaricato: %s (UTC)\n", date)
	var counts []string
	for i, r := range registries {
		if count[i] > 0 {
			counts = append(counts, fmt.Sprintf("%s %d", r.name, count[i]))
		}
	}
	fmt.Fprintf(&head, "# voci: %s\n", strings.Join(counts, ", "))
	fmt.Fprintf(&head, "# escluse: %d private o senza nome, %d blocchi suddivisi dalla IEEE Registration Authority, %d prefissi con più organizzazioni\n",
		l.private, l.ieee, ambiguous)
	fmt.Fprintln(&head, "# nomi abbreviati da oui.Normalize; righe: prefisso esadecimale (6, 7 o 9 cifre), TAB, nome")

	size, err := write(out, head.String(), lines)
	if err != nil {
		return err
	}
	fmt.Printf("Scritto %s (%d byte): %s; %d nomi distinti\n", out, size, strings.Join(counts, ", "), len(distinct))
	fmt.Printf("Escluse: %d private o senza nome, %d blocchi suddivisi dalla IEEE Registration Authority, %d prefissi con più organizzazioni\n",
		l.private, l.ieee, ambiguous)
	return nil
}

// read aggiunge all'elenco le voci di un file CSV della IEEE (colonne
// Registry, Assignment, Organization Name, Organization Address).
func (l *list) read(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	r := csv.NewReader(bufio.NewReader(f))
	r.FieldsPerRecord = -1
	r.ReuseRecord = true
	rows := 0
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		if rows == 0 {
			// Intestazione: se manca, il file non è l'elenco (per esempio una
			// pagina di errore) e non va usato.
			if len(rec) < 3 || strings.TrimPrefix(rec[0], "\ufeff") != "Registry" || rec[1] != "Assignment" || rec[2] != "Organization Name" {
				return fmt.Errorf("%s: intestazione inattesa %q", file, rec)
			}
			rows++
			continue
		}
		rows++
		if len(rec) < 3 {
			return fmt.Errorf("%s: riga %d con %d colonne", file, rows, len(rec))
		}
		reg := slices.IndexFunc(registries, func(r registry) bool { return r.name == rec[0] })
		p := strings.ToUpper(strings.TrimSpace(rec[1]))
		if reg < 0 || len(p) != registries[reg].digits || strings.Trim(p, "0123456789ABCDEF") != "" {
			return fmt.Errorf("%s: riga %d non valida: %q", file, rows, rec)
		}
		name := oui.Normalize(rec[2])
		switch {
		case name == "" || strings.EqualFold(name, "Private"):
			l.private++
			continue
		case strings.EqualFold(name, "IEEE Registration Authority"):
			l.ieee++
			continue
		}
		if !slices.Contains(l.names[p], name) {
			l.names[p] = append(l.names[p], name)
		}
		l.reg[p] = reg
	}
	if rows < 2 {
		return fmt.Errorf("%s: nessuna voce", file)
	}
	return nil
}

// write scrive il file compresso accanto alla destinazione e poi lo sposta al
// suo posto, così un errore non lascia un file a metà. Restituisce la
// dimensione.
func write(out, head string, lines []string) (int64, error) {
	tmp, err := os.CreateTemp(filepath.Dir(out), ".oui-*.gz")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	zw, err := gzip.NewWriterLevel(tmp, gzip.BestCompression)
	if err != nil {
		tmp.Close()
		return 0, err
	}
	bw := bufio.NewWriter(zw)
	bw.WriteString(head)
	for _, line := range lines {
		bw.WriteString(line)
		bw.WriteByte('\n')
	}
	if err := errors.Join(bw.Flush(), zw.Close()); err != nil {
		tmp.Close()
		return 0, err
	}
	st, err := tmp.Stat()
	if err := errors.Join(err, tmp.Close()); err != nil {
		return 0, err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return 0, err
	}
	return st.Size(), os.Rename(tmp.Name(), out)
}
