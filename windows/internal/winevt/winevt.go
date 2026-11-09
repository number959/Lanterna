// Package winevt legge i registri eventi di Windows con le API documentate
// di wevtapi.dll (EvtQuery, EvtNext, EvtRender): solo lettura, senza
// PowerShell. Di ogni evento tiene fonte, codice, livello, ora e i valori di
// EventData; il nome del computer e l'utente, che pure sono nell'XML, non
// vengono letti.
package winevt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Event è un evento del registro.
type Event struct {
	Provider string
	ID       int
	Level    int
	Time     time.Time
	// Data sono i valori di EventData in ordine; Named gli stessi per nome,
	// per gli eventi che li hanno (provider con manifesto).
	Data  []string
	Named map[string]string
}

// Get restituisce il valore per nome o, se l'evento non ha nomi, per
// posizione (gli eventi classici, come "Application Error" su Windows 10,
// hanno i valori senza nome); "" se manca.
func (e Event) Get(name string, pos int) string {
	if v, ok := e.Named[name]; ok {
		return v
	}
	if len(e.Named) == 0 && pos >= 0 && pos < len(e.Data) {
		return e.Data[pos]
	}
	return ""
}

// Errori riconosciuti.
var (
	ErrDenied    = errors.New("accesso negato al registro eventi")
	ErrNoChannel = errors.New("registro eventi non presente")
)

type xmlEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

// ParseXML interpreta l'XML di un evento (EvtRender con EvtRenderEventXml).
func ParseXML(b []byte) (Event, error) {
	var x xmlEvent
	if err := xml.Unmarshal(b, &x); err != nil {
		return Event{}, fmt.Errorf("evento non leggibile: %w", err)
	}
	var e Event
	e.Provider = strings.TrimSpace(x.System.Provider.Name)
	if _, err := fmt.Sscan(strings.TrimSpace(x.System.EventID), &e.ID); err != nil {
		return Event{}, fmt.Errorf("evento senza codice")
	}
	fmt.Sscan(strings.TrimSpace(x.System.Level), &e.Level)
	if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(x.System.TimeCreated.SystemTime)); err == nil {
		e.Time = t.UTC()
	}
	for _, d := range x.EventData.Data {
		v := strings.TrimSpace(d.Value)
		e.Data = append(e.Data, v)
		if d.Name != "" {
			if e.Named == nil {
				e.Named = map[string]string{}
			}
			e.Named[d.Name] = v
		}
	}
	return e, nil
}

// XPath costruisce l'interrogazione per i codici indicati degli ultimi days
// giorni, facoltativamente per fonte.
func XPath(ids []int, days int, providers ...string) string {
	var conds []string
	if len(providers) > 0 {
		var p []string
		for _, n := range providers {
			p = append(p, fmt.Sprintf("@Name='%s'", strings.ReplaceAll(n, "'", "")))
		}
		conds = append(conds, "Provider["+strings.Join(p, " or ")+"]")
	}
	if len(ids) > 0 {
		var p []string
		for _, id := range ids {
			p = append(p, fmt.Sprintf("EventID=%d", id))
		}
		conds = append(conds, "("+strings.Join(p, " or ")+")")
	}
	if days > 0 {
		conds = append(conds, fmt.Sprintf("TimeCreated[timediff(@SystemTime) <= %d]", int64(days)*86400000))
	}
	if len(conds) == 0 {
		return "*"
	}
	return "*[System[" + strings.Join(conds, " and ") + "]]"
}
