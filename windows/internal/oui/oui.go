// Package oui riconosce il produttore di un dispositivo di rete dal suo
// indirizzo MAC, senza collegarsi a Internet. In un MAC universale (assegnato
// dal produttore) i primi 24, 28 o 36 bit sono il blocco che la IEEE
// Registration Authority ha assegnato a un'organizzazione: MA-L (24 bit),
// MA-M (28 bit) o MA-S (36 bit). L'elenco pubblico dei blocchi è incorporato
// nell'eseguibile in oui.txt.gz, rigenerato da scripts/oui.sh con
// gen/main.go, e si decomprime al primo uso in una struttura compatta.
package oui

import (
	"bufio"
	"bytes"
	"cmp"
	"compress/gzip"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
)

//go:embed oui.txt.gz
var embedded []byte

// digits sono le lunghezze dei prefissi in cifre esadecimali: MA-S, MA-M e
// MA-L, dal più lungo, perché vince il blocco più specifico.
var digits = [3]int{9, 7, 6}

// nameBits sono i bit bassi di ogni voce, che indicano il nome; il prefisso
// (al massimo 36 bit) sta nei bit alti.
const nameBits = 24

// index è l'elenco decompresso.
type index struct {
	// tables[i] contiene i blocchi con prefisso di digits[i] cifre: in ogni
	// voce prefisso << nameBits | numero del nome, in ordine crescente per la
	// ricerca binaria. Otto byte per blocco.
	tables [3][]uint64
	// names contiene i nomi distinti uno dopo l'altro, ends la fine di
	// ciascuno: un nome usato da mille blocchi (Huawei, Apple) è scritto una
	// volta sola.
	names string
	ends  []uint32
	date  string
}

// load decomprime l'elenco al primo uso; se non si riesce a leggerlo (non
// dovrebbe succedere: lo controllano i test) l'elenco resta vuoto.
var load = sync.OnceValue(func() *index {
	ix, err := parse(bytes.NewReader(embedded))
	if err != nil {
		return &index{}
	}
	return ix
})

// Lookup restituisce il produttore del dispositivo con questo indirizzo MAC,
// con il nome abbreviato (per esempio "Cisco", "Brother", "Hikvision").
// L'indirizzo può essere scritto come aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff,
// aabb.ccdd.eeff o aabbccddeeff (le forme di net.ParseMAC), in maiuscolo o
// minuscolo.
//
// Restituisce "" quando il produttore non si può dire: organizzazione assente
// dall'elenco pubblico o elencata come "Private", indirizzo non valido, di
// gruppo (multicast o broadcast), nullo (prefisso 00:00:00) o amministrato
// localmente (bit 0x02 del primo ottetto), come i MAC casuali di telefoni e
// PC e quelli delle schede virtuali.
func Lookup(mac string) string {
	return load().lookup(mac)
}

// Count restituisce il numero di blocchi dell'elenco incorporato, 0 se non si
// è potuto leggere.
func Count() int {
	ix := load()
	return len(ix.tables[0]) + len(ix.tables[1]) + len(ix.tables[2])
}

// Date restituisce il giorno (UTC, AAAA-MM-GG) in cui l'elenco è stato
// scaricato dalla IEEE, "" se non si è potuto leggere.
func Date() string {
	return load().date
}

func (ix *index) lookup(mac string) string {
	hw, err := net.ParseMAC(mac)
	// Solo indirizzi a 48 bit, individuali (bit 0x01 a zero) e universali
	// (bit 0x02 a zero). Il prefisso 00:00:00, il primo assegnato (a Xerox),
	// in pratica si trova solo negli indirizzi nulli o non inizializzati.
	if err != nil || len(hw) != 6 || hw[0]&0x03 != 0 || hw[0]|hw[1]|hw[2] == 0 {
		return ""
	}
	var v uint64
	for _, b := range hw {
		v = v<<8 | uint64(b)
	}
	for i := range ix.tables {
		if name, ok := ix.find(i, v>>(48-4*digits[i])); ok {
			return name
		}
	}
	return ""
}

// find cerca il prefisso p nella tabella i (ricerca binaria).
func (ix *index) find(i int, p uint64) (string, bool) {
	t := ix.tables[i]
	j, ok := slices.BinarySearchFunc(t, p, func(e, p uint64) int { return cmp.Compare(e>>nameBits, p) })
	if !ok {
		return "", false
	}
	return ix.name(t[j] & (1<<nameBits - 1)), true
}

// name restituisce il nome numero i.
func (ix *index) name(i uint64) string {
	var start uint32
	if i > 0 {
		start = ix.ends[i-1]
	}
	return ix.names[start:ix.ends[i]]
}

// parse legge l'elenco compresso: righe "PREFISSO<TAB>Nome", con il prefisso
// di 6, 7 o 9 cifre esadecimali, e commenti che cominciano con "#", tra cui
// quello con il giorno del download ("# scaricato: AAAA-MM-GG (UTC)").
func parse(r io.Reader) (*index, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	ix := &index{}
	ids := make(map[string]uint32)
	var names strings.Builder
	sc := bufio.NewScanner(zr)
	for line := 1; sc.Scan(); line++ {
		b := sc.Bytes()
		if len(b) > 0 && b[0] == '#' {
			if d, ok := bytes.CutPrefix(b, []byte("# scaricato: ")); ok {
				ix.date, _, _ = strings.Cut(string(d), " ")
			}
			continue
		}
		hex, name, ok := bytes.Cut(b, []byte{'\t'})
		t := slices.Index(digits[:], len(hex))
		p, okHex := parseHex(hex)
		if !ok || t < 0 || !okHex || len(name) == 0 {
			return nil, fmt.Errorf("riga %d non valida: %q", line, b)
		}
		id, ok := ids[string(name)]
		if !ok {
			if len(ix.ends) == 1<<nameBits {
				return nil, errors.New("troppi nomi distinti")
			}
			id = uint32(len(ix.ends))
			ids[string(name)] = id
			names.Write(name)
			ix.ends = append(ix.ends, uint32(names.Len()))
		}
		ix.tables[t] = append(ix.tables[t], p<<nameBits|uint64(id))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// Copie della misura giusta: le aggiunte lasciano fino a metà dello spazio
	// inutilizzato.
	ix.names = strings.Clone(names.String())
	ix.ends = slices.Clone(ix.ends)
	for i := range ix.tables {
		ix.tables[i] = slices.Clone(ix.tables[i])
		slices.Sort(ix.tables[i])
	}
	return ix, nil
}

// parseHex legge un numero esadecimale senza segno di al massimo 16 cifre.
func parseHex(b []byte) (uint64, bool) {
	if len(b) == 0 || len(b) > 16 {
		return 0, false
	}
	var v uint64
	for _, c := range b {
		switch {
		case '0' <= c && c <= '9':
			c -= '0'
		case 'A' <= c && c <= 'F':
			c -= 'A' - 10
		case 'a' <= c && c <= 'f':
			c -= 'a' - 10
		default:
			return 0, false
		}
		v = v<<4 | uint64(c)
	}
	return v, true
}
