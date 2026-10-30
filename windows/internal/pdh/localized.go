package pdh

import (
	"encoding/binary"
	"strings"
	"sync"
	"unicode/utf16"
)

// Traduzione dei nomi dei contatori per i Windows senza risorse in inglese.
//
// PdhAddEnglishCounterW trova i nomi inglesi nella tabella "009". Per gli
// insiemi di contatori registrati con un manifesto (versione 2: Processor
// Information, Thermal Zone Information, GPU Engine, Energy Meter...) quella
// tabella si riempie dalle risorse del fornitore, e su un Windows installato
// solo in italiano (o in tedesco) contiene i nomi localizzati: il percorso
// inglese fallisce con PDH_CSTATUS_NO_OBJECT. In quel caso si cerca
// l'insieme per nome inglese con le funzioni di registrazione della versione
// 2 (PerfEnumerateCounterSet, PerfQueryCounterSetRegistrationInfo con la
// lingua 0x0409), se ne leggono i nomi nelle lingue dell'interfaccia e si
// riprova con il percorso localizzato. Lo stesso rimedio è documentato e
// provato su Windows 11 in tedesco dal progetto windows_exporter (PR 2709).

// GUID di un insieme di contatori, come 16 byte.
type GUID [16]byte

// registry legge la registrazione degli insiemi di contatori della versione
// 2; su Windows sono le funzioni di advapi32, nei test un sostituto.
type registry struct {
	sets     func() ([]GUID, error)
	setName  func(g GUID, lang uint16) (string, bool)
	counters func(g GUID, lang uint16) (map[uint32]string, bool)
	// langs sono le lingue dell'interfaccia (utente e sistema).
	langs func() []uint16
	// english: considera anche l'inglese tra le lingue (per le prove).
	english bool
}

type translation struct {
	object   string
	counters map[string]string // nome inglese in minuscolo → nome localizzato
}

// translator traduce i percorsi inglesi; l'indice si costruisce alla prima
// richiesta e le traduzioni restano in memoria.
type translator struct {
	reg   registry
	once  sync.Once
	mu    sync.Mutex
	index map[string]GUID
	cache map[string][]translation
}

const langEnglish = 0x0409

// isEnglish confronta la lingua principale (i 10 bit bassi dell'identificativo).
func isEnglish(lang uint16) bool { return lang&0x3FF == 0x09 }

func (t *translator) build() {
	t.index = map[string]GUID{}
	t.cache = map[string][]translation{}
	sets, err := t.reg.sets()
	if err != nil {
		return
	}
	for _, g := range sets {
		if name, ok := t.reg.setName(g, langEnglish); ok && name != "" {
			t.index[strings.ToLower(name)] = g
		}
	}
}

// translations restituisce i nomi localizzati dell'insieme, una voce per
// lingua dell'interfaccia diversa dall'inglese.
func (t *translator) translations(object string) []translation {
	t.once.Do(t.build)
	t.mu.Lock()
	defer t.mu.Unlock()
	key := strings.ToLower(object)
	if tr, found := t.cache[key]; found {
		return tr
	}
	var out []translation
	g, found := t.index[key]
	if found {
		english, _ := t.reg.counters(g, langEnglish)
		seen := map[uint16]bool{}
		for _, lang := range t.reg.langs() {
			if lang == 0 || seen[lang] || (isEnglish(lang) && !t.reg.english) {
				continue
			}
			seen[lang] = true
			name, ok := t.reg.setName(g, lang)
			if !ok || name == "" {
				continue
			}
			local, _ := t.reg.counters(g, lang)
			tr := translation{object: name, counters: map[string]string{}}
			for id, en := range english {
				if l := local[id]; l != "" {
					tr.counters[strings.ToLower(en)] = l
				}
			}
			out = append(out, tr)
		}
	}
	t.cache[key] = out
	return out
}

// paths restituisce i percorsi localizzati per un percorso inglese, nessuno
// se l'insieme non è della versione 2 o non ha traduzioni.
func (t *translator) paths(path string) []string {
	object, instance, counter, ok := splitPath(path)
	if !ok {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, tr := range t.translations(object) {
		c := tr.counters[strings.ToLower(counter)]
		if c == "" {
			continue
		}
		p := joinPath(tr.object, instance, c)
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// splitPath divide `\Oggetto(Istanza)\Contatore` (l'istanza è facoltativa).
func splitPath(path string) (object, instance, counter string, ok bool) {
	if !strings.HasPrefix(path, `\`) {
		return "", "", "", false
	}
	rest := path[1:]
	i := strings.LastIndex(rest, `\`)
	if i <= 0 || i == len(rest)-1 {
		return "", "", "", false
	}
	object, counter = rest[:i], rest[i+1:]
	if strings.HasSuffix(object, ")") {
		if j := strings.Index(object, "("); j > 0 {
			object, instance = object[:j], object[j+1:len(object)-1]
		}
	}
	return object, instance, counter, object != ""
}

func joinPath(object, instance, counter string) string {
	if instance != "" {
		return `\` + object + "(" + instance + `)\` + counter
	}
	return `\` + object + `\` + counter
}

// utf16z decodifica una stringa UTF-16LE terminata da zero.
func utf16z(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// parseCounterNames legge la risposta a PERF_REG_COUNTER_NAME_STRINGS:
// PERF_STRING_BUFFER_HEADER (dimensione, numero di contatori), poi per ogni
// contatore PERF_STRING_COUNTER_HEADER (identificativo, scostamento della
// stringa dall'inizio del buffer; 0xFFFFFFFF se manca) e infine le stringhe.
func parseCounterNames(b []byte) map[uint32]string {
	out := map[uint32]string{}
	if len(b) < 8 {
		return out
	}
	n := binary.LittleEndian.Uint32(b[4:])
	for k := uint32(0); k < n; k++ {
		h := 8 + int(k)*8
		if h+8 > len(b) {
			break
		}
		id := binary.LittleEndian.Uint32(b[h:])
		off := binary.LittleEndian.Uint32(b[h+4:])
		if off == 0xFFFFFFFF || int(off) >= len(b) {
			continue
		}
		if s := utf16z(b[off:]); s != "" {
			out[id] = s
		}
	}
	return out
}
