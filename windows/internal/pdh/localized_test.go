package pdh

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"unicode/utf16"
)

func TestSplitJoinPath(t *testing.T) {
	for _, c := range []struct {
		in                 string
		obj, inst, counter string
		ok                 bool
	}{
		{`\Processor Information(*)\% Processor Performance`, "Processor Information", "*", "% Processor Performance", true},
		{`\Processor Information(_Total)\% Performance Limit`, "Processor Information", "_Total", "% Performance Limit", true},
		{`\Memory\Pages/sec`, "Memory", "", "Pages/sec", true},
		{`\PhysicalDisk(*)\Avg. Disk sec/Transfer`, "PhysicalDisk", "*", "Avg. Disk sec/Transfer", true},
		{`Memory\Pages/sec`, "", "", "", false},
		{`\Memory`, "", "", "", false},
		{`\Memory\`, "", "", "", false},
	} {
		obj, inst, counter, ok := splitPath(c.in)
		if ok != c.ok || obj != c.obj || inst != c.inst || counter != c.counter {
			t.Errorf("splitPath(%q) = %q %q %q %v", c.in, obj, inst, counter, ok)
			continue
		}
		if ok && joinPath(obj, inst, counter) != c.in {
			t.Errorf("joinPath non ricompone %q", c.in)
		}
	}
}

// names costruisce una risposta a PERF_REG_COUNTER_NAME_STRINGS.
func names(m map[uint32]string, order []uint32) []byte {
	head := make([]byte, 8+8*len(order))
	binary.LittleEndian.PutUint32(head[4:], uint32(len(order)))
	var strs []byte
	for k, id := range order {
		binary.LittleEndian.PutUint32(head[8+8*k:], id)
		s, found := m[id]
		if !found {
			binary.LittleEndian.PutUint32(head[12+8*k:], 0xFFFFFFFF)
			continue
		}
		binary.LittleEndian.PutUint32(head[12+8*k:], uint32(len(head)+len(strs)))
		for _, u := range utf16.Encode([]rune(s)) {
			strs = binary.LittleEndian.AppendUint16(strs, u)
		}
		strs = append(strs, 0, 0)
	}
	b := append(head, strs...)
	binary.LittleEndian.PutUint32(b, uint32(len(b)))
	return b
}

func TestParseCounterNames(t *testing.T) {
	b := names(map[uint32]string{2: "% Prestazioni processore", 6: "Frequenza processore"}, []uint32{2, 4, 6})
	got := parseCounterNames(b)
	want := map[uint32]string{2: "% Prestazioni processore", 6: "Frequenza processore"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nomi: %v", got)
	}
	// Buffer troncato o scostamenti fuori misura: nessun panico, si salta.
	if len(parseCounterNames(b[:12])) != 0 || len(parseCounterNames(nil)) != 0 {
		t.Error("buffer troncato")
	}
	bad := names(map[uint32]string{1: "x"}, []uint32{1})
	binary.LittleEndian.PutUint32(bad[12:], 9999)
	if len(parseCounterNames(bad)) != 0 {
		t.Error("scostamento fuori dal buffer")
	}
	if utf16z([]byte{'a', 0, 0xE8, 0, 0, 0, 'z', 0}) != "aè" {
		t.Error("stringa UTF-16")
	}
}

func TestTranslator(t *testing.T) {
	proc := GUID{1}
	disk := GUID{2}
	queries := 0
	reg := registry{
		sets: func() ([]GUID, error) { return []GUID{proc, disk}, nil },
		setName: func(g GUID, lang uint16) (string, bool) {
			queries++
			switch {
			case g == proc && lang == langEnglish:
				return "Processor Information", true
			case g == proc && lang == 0x0410:
				return "Informazioni processore", true
			case g == disk && lang == langEnglish:
				return "Disco", true // insieme della versione 2 senza traduzioni utili
			}
			return "", false
		},
		counters: func(g GUID, lang uint16) (map[uint32]string, bool) {
			if g != proc {
				return nil, false
			}
			if lang == langEnglish {
				return map[uint32]string{2: "% Processor Performance", 4: "Processor Frequency", 8: "% C1 Time"}, true
			}
			return map[uint32]string{2: "% Prestazioni processore", 4: "Frequenza processore"}, true
		},
		langs: func() []uint16 { return []uint16{0x0410, 0x0410, 0x0409, 0} },
	}
	tr := &translator{reg: reg}
	got := tr.paths(`\Processor Information(*)\% Processor Performance`)
	if !reflect.DeepEqual(got, []string{`\Informazioni processore(*)\% Prestazioni processore`}) {
		t.Fatalf("percorsi: %q", got)
	}
	// Maiuscole e minuscole non contano; un contatore senza traduzione non dà percorsi.
	if got := tr.paths(`\processor information(_Total)\processor frequency`); !reflect.DeepEqual(got, []string{`\Informazioni processore(_Total)\Frequenza processore`}) {
		t.Errorf("percorso in minuscolo: %q", got)
	}
	if got := tr.paths(`\Processor Information(_Total)\% C1 Time`); got != nil {
		t.Errorf("contatore senza traduzione: %q", got)
	}
	// Insiemi della versione 1 o sconosciuti: nessun percorso.
	if tr.paths(`\Memory\Pages/sec`) != nil || tr.paths(`\Disco\X`) != nil || tr.paths("non valido") != nil {
		t.Error("insieme sconosciuto")
	}
	// Le traduzioni restano in memoria: nessuna nuova richiesta.
	before := queries
	tr.paths(`\Processor Information(*)\% Processor Performance`)
	if queries != before {
		t.Errorf("traduzione ripetuta: %d richieste in più", queries-before)
	}
	// Con l'interruttore per le prove anche l'inglese conta come lingua.
	reg.english = true
	reg.langs = func() []uint16 { return []uint16{0x0409} }
	en := &translator{reg: reg}
	if got := en.paths(`\Processor Information(*)\Processor Frequency`); !reflect.DeepEqual(got, []string{`\Processor Information(*)\Processor Frequency`}) {
		t.Errorf("inglese forzato: %q", got)
	}
	// Errore nell'elenco degli insiemi: nessun percorso, nessun panico.
	broken := &translator{reg: registry{sets: func() ([]GUID, error) { return nil, errors.New("no") }}}
	if broken.paths(`\Processor Information(*)\X`) != nil {
		t.Error("elenco non leggibile")
	}
}
