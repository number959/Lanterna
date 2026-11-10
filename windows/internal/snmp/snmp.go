// Package snmp interroga in sola lettura, su richiesta esplicita del tecnico,
// un router o uno switch di livello 3 della rete interna per ricostruire la
// struttura della rete: le VLAN, le sottoreti e i gateway del dispositivo, i
// dispositivi che ha visto (tabella ARP), i vicini LLDP e quale indirizzo MAC
// sta dietro a quale porta. Così Polaris scopre le altre VLAN e disegna la
// mappa della rete senza contattare i singoli dispositivi.
//
// Le credenziali le scrive il tecnico per ogni lettura: non vengono salvate,
// non finiscono nei registri né nei messaggi di errore, e alla fine si
// cancellano le chiavi che ne derivano. Si interroga un solo indirizzo IPv4
// privato (RFC 1918): niente nomi, intervalli o broadcast, e nessuna
// community "di prova" (public, private): si usa solo quella indicata.
//
// Il ritmo è prudente come nelle altre analisi dell'infrastruttura: una
// richiesta alla volta con una pausa minima tra l'una e l'altra, GETBULK con
// poche righe per risposta, un limite di righe per tabella e un tempo massimo
// per l'intera lettura.
//
// Si chiedono solo gli oggetti elencati in tables.go. Il testo libero scritto
// dagli amministratori, che può contenere nomi di persone, non si chiede né
// si esporta: sysContact, sysLocation, ifAlias, la descrizione delle porte
// annunciata con LLDP (lldpRemPortDesc, lldpLocPortDesc) e gli identificativi
// LLDP che sono alias assegnati a mano (sottotipi interfaceAlias,
// chassisComponent, portComponent). Un GETBULK può restituire qualche oggetto
// oltre la fine della colonna letta: si scarta all'arrivo, senza esaminarlo;
// nessuna delle colonne lette con GETBULK è seguita da quegli oggetti.
package snmp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

func init() {
	// gosnmp tiene in una cache globale le chiavi ricavate dalle password
	// SNMPv3, con la password stessa dentro la chiave della cache: si spegne,
	// così le password restano in memoria solo per la durata di una lettura.
	gosnmp.PasswordCaching(false)
}

// Creds sono le credenziali scritte dal tecnico per una sola lettura. Collect
// non le conserva: anche il chiamante non deve salvarle né registrarle.
// String, GoString e MarshalJSON nascondono community, utente e password,
// nel caso finiscano per sbaglio in un messaggio o in un registro.
type Creds struct {
	Version   string `json:"version"`             // "2c" oppure "3"
	Community string `json:"community,omitempty"` // solo SNMPv2c
	User      string `json:"user,omitempty"`      // SNMPv3
	// Auth: "" (nessuna), "SHA" (SHA-1), "SHA224", "SHA256", "SHA384",
	// "SHA512" oppure "MD5", solo per i dispositivi vecchi che non hanno altro.
	Auth     string `json:"auth,omitempty"`
	AuthPass string `json:"authPass,omitempty"`
	// Priv: "" (nessuna), "AES" (AES-128) oppure "DES", solo per i
	// dispositivi vecchi che non hanno altro.
	Priv     string `json:"priv,omitempty"`
	PrivPass string `json:"privPass,omitempty"`
}

// String descrive le credenziali senza i segreti.
func (c Creds) String() string {
	if normVersion(c.Version) == "3" {
		return "SNMPv3 (utente e password nascosti)"
	}
	return "SNMPv2c (community nascosta)"
}

// GoString vale per %#v, che altrimenti mostrerebbe tutti i campi.
func (c Creds) GoString() string { return c.String() }

// MarshalJSON scrive solo versione e protocolli, mai community, utente e password.
func (c Creds) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Version string `json:"version"`
		Auth    string `json:"auth,omitempty"`
		Priv    string `json:"priv,omitempty"`
	}{c.Version, c.Auth, c.Priv})
}

// Options regola il ritmo e i limiti della lettura.
type Options struct {
	Timeout        time.Duration // attesa massima di una risposta
	Retries        int           // nuovi tentativi dopo un'attesa scaduta (0: nessuno)
	Interval       time.Duration // pausa minima tra la fine di una richiesta e l'inizio della successiva
	MaxRepetitions uint32        // righe chieste con ogni GETBULK
	MaxRows        int           // righe al massimo per tabella
	Deadline       time.Duration // durata massima dell'intera lettura
}

// Prudent è il ritmo predefinito: una richiesta alla volta, almeno 50 ms tra
// una risposta e la richiesta successiva, 16 righe per GETBULK, al massimo
// 4096 righe per tabella e un minuto per tutta la lettura. Su uno switch di
// 48 porte servono un centinaio di richieste, una decina di secondi.
var Prudent = Options{
	Timeout:        2 * time.Second,
	Retries:        1,
	Interval:       50 * time.Millisecond,
	MaxRepetitions: 16,
	MaxRows:        4096,
	Deadline:       60 * time.Second,
}

// normalized sostituisce i valori a zero con quelli di Prudent e riporta gli
// altri entro limiti prudenti. Retries a zero resta zero.
func (o Options) normalized() Options {
	p := Prudent
	if o.Timeout <= 0 {
		o.Timeout = p.Timeout
	}
	o.Timeout = min(o.Timeout, 10*time.Second)
	o.Retries = max(0, min(o.Retries, 3))
	if o.Interval <= 0 {
		o.Interval = p.Interval
	}
	if o.MaxRepetitions == 0 {
		o.MaxRepetitions = p.MaxRepetitions
	}
	o.MaxRepetitions = min(o.MaxRepetitions, 50)
	if o.MaxRows <= 0 {
		o.MaxRows = p.MaxRows
	}
	o.MaxRows = min(o.MaxRows, 65536)
	if o.Deadline <= 0 {
		o.Deadline = p.Deadline
	}
	o.Deadline = min(o.Deadline, 10*time.Minute)
	return o
}

// Result è quanto si è riusciti a leggere. Ogni sezione ha il proprio stato
// in Sections: una risposta parziale è normale (tabelle che il dispositivo
// non gestisce, limiti di righe, tempo massimo).
type Result struct {
	Target     string   `json:"target"`
	Version    string   `json:"version"` // "2c" oppure "3"
	StartedAt  string   `json:"startedAt"`
	DurationMs int64    `json:"durationMs"`
	Requests   int      `json:"requests"`           // pacchetti SNMP inviati, nuovi tentativi compresi
	Stopped    string   `json:"stopped,omitempty"`  // perché la lettura si è fermata prima della fine
	Warnings   []string `json:"warnings,omitempty"` // avvertenze sulla sicurezza della configurazione usata

	System        *System    `json:"system,omitempty"`
	Interfaces    []Iface    `json:"interfaces"`
	Vlans         []Vlan     `json:"vlans"`
	LldpNeighbors []Neighbor `json:"lldpNeighbors"`
	Arp           []ArpEntry `json:"arp"`
	Fdb           []FdbEntry `json:"fdb"`
	Sections      Sections   `json:"sections"`
}

// System sono i dati generali del dispositivo (SNMPv2-MIB). sysContact e
// sysLocation non si leggono: possono contenere nomi di persone.
type System struct {
	Descr     string `json:"descr,omitempty"`     // sysDescr, al massimo 200 caratteri
	ObjectID  string `json:"objectId,omitempty"`  // sysObjectID: produttore e modello
	Name      string `json:"name,omitempty"`      // sysName
	UptimeSec int64  `json:"uptimeSec,omitempty"` // sysUpTime: secondi dall'avvio dell'agente SNMP (si azzera dopo 497 giorni)
	ChassisID string `json:"chassisId,omitempty"` // lldpLocChassisId: come lo vedono i vicini LLDP
}

// Iface è un'interfaccia con indirizzi IPv4 o che ha l'aspetto di
// un'interfaccia VLAN; le porte di accesso non si elencano. Nomi e
// descrizioni sono quelli generati dal dispositivo: ifAlias, la descrizione
// scritta dall'amministratore, non si legge.
type Iface struct {
	Index  int       `json:"index"`            // ifIndex
	Name   string    `json:"name,omitempty"`   // ifName (Vl10, Gi1/0/1)
	Descr  string    `json:"descr,omitempty"`  // ifDescr (Vlan10, GigabitEthernet1/0/1)
	Type   int       `json:"type,omitempty"`   // ifType IANA: 136 l3ipvlan, 135 l2vlan, 53 propVirtual, 24 softwareLoopback
	VlanID int       `json:"vlanId,omitempty"` // VLAN dedotta dal nome (Vlan10, Vl10, Vlanif10)
	IPs    []IfaceIP `json:"ips"`
}

// IfaceIP è un indirizzo IPv4 dell'interfaccia (ipAddrTable).
type IfaceIP struct {
	IP     string `json:"ip"`
	Mask   string `json:"mask,omitempty"`
	Prefix int    `json:"prefix"`           // 0 con Subnet vuota: maschera assente o non valida
	Subnet string `json:"subnet,omitempty"` // rete in notazione CIDR: 192.168.10.0/24
}

// Vlan è una VLAN configurata sul dispositivo.
type Vlan struct {
	ID   int    `json:"id"`
	Name string `json:"name,omitempty"`
	// State compare solo con CISCO-VTP-MIB e solo se la VLAN non è operativa:
	// suspended, mtuTooBigForDevice, mtuTooBigForTrunk.
	State string `json:"state,omitempty"`
}

// Neighbor è un vicino annunciato con LLDP su una porta del dispositivo. La
// descrizione della porta (lldpRemPortDesc) non si legge: è il testo che
// l'amministratore del vicino ha scritto sull'interfaccia. Gli identificativi
// che sono alias scritti a mano restano vuoti; il tipo dice quale era.
type Neighbor struct {
	LocalPortNum  int      `json:"localPortNum"`            // lldpRemLocalPortNum
	LocalPort     string   `json:"localPort,omitempty"`     // porta locale, da lldpLocPortId (Gi1/0/1, 3)
	ChassisID     string   `json:"chassisId,omitempty"`     // identificativo del vicino
	ChassisIDType string   `json:"chassisIdType,omitempty"` // macAddress, networkAddress, interfaceName, local...
	PortID        string   `json:"portId,omitempty"`        // porta del vicino
	PortIDType    string   `json:"portIdType,omitempty"`    // interfaceName, macAddress, local...
	SysName       string   `json:"sysName,omitempty"`
	CapsEnabled   []string `json:"capsEnabled,omitempty"` // bridge, router, wlanAccessPoint, telephone...
	MgmtIP        string   `json:"mgmtIp,omitempty"`      // indirizzo di gestione IPv4 annunciato
}

// ArpEntry è una riga della tabella ARP: un dispositivo visto su un'interfaccia.
type ArpEntry struct {
	IfIndex int    `json:"ifIndex"`
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
}

// FdbEntry dice dietro quale porta lo switch ha visto un indirizzo MAC.
type FdbEntry struct {
	MAC        string `json:"mac"`
	Port       string `json:"port,omitempty"`    // nome della porta (ifName), se noto
	BridgePort int    `json:"bridgePort"`        // numero di porta del bridge (dot1dBasePort)
	IfIndex    int    `json:"ifIndex,omitempty"` // interfaccia della porta, se nota
	FdbID      int    `json:"fdbId,omitempty"`   // solo Q-BRIDGE-MIB: database del MAC, spesso uguale alla VLAN
}

// Sections è lo stato di ogni sezione.
type Sections struct {
	System     Status `json:"system"`
	Interfaces Status `json:"interfaces"`
	Vlans      Status `json:"vlans"`
	Lldp       Status `json:"lldp"`
	Arp        Status `json:"arp"`
	Fdb        Status `json:"fdb"`
}

// Stati di una sezione.
const (
	StateOK      = "ok"      // letta per intero (anche vuota, se il dispositivo gestisce la tabella)
	StatePartial = "partial" // letta in parte: limite di righe, errore o interruzione
	StateAbsent  = "absent"  // nessun dato: tabella non gestita dal dispositivo o vuota
	StateError   = "error"   // nessun dato per un errore
	StateSkipped = "skipped" // non letta: la lettura si è fermata prima
)

// Status è l'esito della lettura di una sezione.
type Status struct {
	State  string `json:"state"`
	Rows   int    `json:"rows"`
	Source string `json:"source,omitempty"` // MIB da cui vengono i dati
	Note   string `json:"note,omitempty"`   // spiegazione in italiano
}

// Kind classifica gli errori per l'interfaccia.
type Kind string

// Tipi di errore.
const (
	KindInvalid     Kind = "invalid"     // indirizzo o credenziali scritti male: nessuna richiesta inviata
	KindNotPrivate  Kind = "notPrivate"  // indirizzo non privato: nessuna richiesta inviata
	KindTimeout     Kind = "timeout"     // nessuna risposta (in SNMPv2c anche la community sbagliata)
	KindAuth        Kind = "auth"        // credenziali SNMPv3 rifiutate
	KindRefused     Kind = "refused"     // porta SNMP chiusa: il dispositivo ha rifiutato
	KindUnreachable Kind = "unreachable" // nessun percorso verso l'indirizzo
	KindDeadline    Kind = "deadline"    // tempo massimo della lettura esaurito
	KindCanceled    Kind = "canceled"    // lettura interrotta
	KindProtocol    Kind = "protocol"    // risposta non valida o errore SNMP non previsto
)

// Error è l'errore di Collect: il messaggio è in italiano e non contiene mai
// community, utente o password.
type Error struct {
	Kind Kind   `json:"kind"`
	Msg  string `json:"message"`
}

func (e *Error) Error() string { return e.Msg }

func invalid(msg string) *Error { return &Error{Kind: KindInvalid, Msg: msg} }

// errDeadline è la causa del contesto quando scade Options.Deadline.
var errDeadline = errors.New("tempo massimo della lettura esaurito")

// Passi comunicati a progress, nell'ordine in cui si eseguono.
const (
	stepSystem     = "Dati del dispositivo"
	stepInterfaces = "Interfacce e indirizzi IP"
	stepVlans      = "VLAN"
	stepLldp       = "Vicini LLDP"
	stepArp        = "Tabella ARP"
	stepFdb        = "Indirizzi MAC per porta"
)

// Collect interroga target e restituisce quanto ha letto. Indirizzo e
// credenziali si controllano prima di inviare qualunque pacchetto. Se il
// dispositivo non risponde alla prima richiesta, o rifiuta le credenziali,
// restituisce solo l'errore. Dopo la prima risposta restituisce sempre il
// risultato, anche parziale: se il dispositivo smette di rispondere o scade
// il tempo massimo, le sezioni successive risultano "skipped" e Stopped dice
// perché. Se ctx viene annullato restituisce il risultato parziale insieme a
// un errore di tipo KindCanceled. progress, se non è nil, riceve il nome di
// ogni passo prima che inizi.
func Collect(ctx context.Context, target string, cr Creds, opt Options, progress func(step string)) (*Result, error) {
	ip, err := checkTarget(target)
	if err != nil {
		return nil, err
	}
	opt = opt.normalized()
	start := time.Now()
	ctx, cancel := context.WithTimeoutCause(ctx, opt.Deadline, errDeadline)
	defer cancel()
	s, err := open(ctx, ip, cr, opt)
	if err != nil {
		return nil, err
	}
	defer s.close()

	res := &Result{
		Target:        ip.String(),
		Version:       "2c",
		StartedAt:     start.UTC().Format(time.RFC3339),
		Warnings:      s.warnings,
		Interfaces:    []Iface{},
		Vlans:         []Vlan{},
		LldpNeighbors: []Neighbor{},
		Arp:           []ArpEntry{},
		Fdb:           []FdbEntry{},
	}
	if s.v3 {
		res.Version = "3"
	}
	c := &collector{s: s, res: res, max: opt.MaxRows, names: map[int]string{}, descr: map[int]string{}}
	step := func(name string) {
		if progress != nil {
			progress(name)
		}
	}

	// La prima richiesta dice se il dispositivo risponde e accetta le credenziali.
	step(stepSystem)
	if err := c.system(); err != nil {
		return nil, err
	}
	var stop *Error
	for _, sec := range []struct {
		step string
		st   *Status
		run  func() *Error
	}{
		{stepInterfaces, &res.Sections.Interfaces, c.interfaces},
		{stepVlans, &res.Sections.Vlans, c.vlans},
		{stepLldp, &res.Sections.Lldp, c.lldp},
		{stepArp, &res.Sections.Arp, c.arp},
		{stepFdb, &res.Sections.Fdb, c.fdb},
	} {
		if stop != nil {
			*sec.st = Status{State: StateSkipped, Note: "non letta: " + stop.Msg}
			continue
		}
		step(sec.step)
		stop = sec.run()
	}
	res.DurationMs = time.Since(start).Milliseconds()
	res.Requests = s.packets
	if stop != nil {
		res.Stopped = stop.Msg
		if stop.Kind == KindCanceled {
			return res, stop
		}
	}
	return res, nil
}

// allowed decide quali indirizzi si possono interrogare. È una variabile
// solo perché i test usano un agente finto su 127.0.0.1: nel programma vale
// sempre privateIPv4.
var allowed = privateIPv4

// privateIPv4 dice se l'indirizzo appartiene a una rete privata IPv4 (RFC 1918).
func privateIPv4(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	return b[0] == 10 || (b[0] == 172 && b[1]&0xf0 == 16) || (b[0] == 192 && b[1] == 168)
}

// checkTarget accetta un solo indirizzo IPv4 privato scritto per esteso. I
// messaggi riportano l'indirizzo solo se è un indirizzo valido: nel campo
// potrebbe essere finita per sbaglio una password.
func checkTarget(target string) (netip.Addr, *Error) {
	s := strings.TrimSpace(target)
	if s == "" {
		return netip.Addr{}, invalid("indica l'indirizzo IPv4 del router o dello switch")
	}
	if strings.ContainsAny(s, "/-,;* \t") {
		return netip.Addr{}, invalid("indica un solo indirizzo IPv4, senza intervalli, elenchi o prefissi")
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Addr{}, invalid("indirizzo non valido: scrivi un indirizzo IPv4 come 192.168.1.1 (nomi e indirizzi IPv6 non sono ammessi)")
	}
	if !allowed(a) {
		return netip.Addr{}, &Error{Kind: KindNotPrivate, Msg: a.String() + " non è un indirizzo privato: SNMP si interroga solo verso router e switch della rete interna (10.x.x.x, da 172.16.x.x a 172.31.x.x, 192.168.x.x)"}
	}
	if b := a.As4(); b[3] == 0 || b[3] == 255 {
		return netip.Addr{}, invalid(a.String() + " finisce con .0 o .255: di solito è l'indirizzo della rete o di broadcast, non quello di un dispositivo")
	}
	return a, nil
}

// maxCommunity è la community più lunga che gosnmp codifica correttamente
// (lunghezza in un solo byte).
const maxCommunity = 127

func normVersion(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "2c", "v2c", "2":
		return "2c"
	case "3", "v3":
		return "3"
	}
	return ""
}

// normProto rende confrontabili "sha-256", "SHA 256" e "SHA256".
func normProto(p string) string {
	return strings.NewReplacer("-", "", " ", "", "_", "").Replace(strings.ToUpper(strings.TrimSpace(p)))
}

// "SHA" è HMAC-SHA-96 (SHA-1, RFC 3414); le varianti SHA-2 sono quelle
// dell'RFC 7860. MD5 serve solo per i dispositivi che non hanno altro.
var authProtocols = map[string]gosnmp.SnmpV3AuthProtocol{
	"":       gosnmp.NoAuth,
	"NONE":   gosnmp.NoAuth,
	"MD5":    gosnmp.MD5,
	"SHA":    gosnmp.SHA,
	"SHA1":   gosnmp.SHA,
	"SHA224": gosnmp.SHA224,
	"SHA256": gosnmp.SHA256,
	"SHA384": gosnmp.SHA384,
	"SHA512": gosnmp.SHA512,
}

// AES è AES-128 in modalità CFB (RFC 3826). DES serve solo per i dispositivi
// che non hanno altro (molti switch "smart" economici).
var privProtocols = map[string]gosnmp.SnmpV3PrivProtocol{
	"":       gosnmp.NoPriv,
	"NONE":   gosnmp.NoPriv,
	"AES":    gosnmp.AES,
	"AES128": gosnmp.AES,
	"DES":    gosnmp.DES,
}

// apply controlla le credenziali e le copia nei parametri di gosnmp, senza
// contattare nessuno. I messaggi non riportano mai i valori scritti.
func (c Creds) apply(g *gosnmp.GoSNMP) *Error {
	switch normVersion(c.Version) {
	case "2c":
		if strings.TrimSpace(c.Community) == "" {
			return invalid("manca la community SNMPv2c")
		}
		if len(c.Community) > maxCommunity {
			return invalid(fmt.Sprintf("community troppo lunga: al massimo %d caratteri", maxCommunity))
		}
		g.Version = gosnmp.Version2c
		g.Community = c.Community
		return nil
	case "3":
		return c.applyV3(g)
	}
	return invalid("versione SNMP non valida: scegli 2c o 3")
}

func (c Creds) applyV3(g *gosnmp.GoSNMP) *Error {
	if strings.TrimSpace(c.User) == "" {
		return invalid("manca il nome utente SNMPv3")
	}
	if len(c.User) > 32 { // usmUserName: SnmpAdminString (SIZE(1..32)), RFC 3414
		return invalid("nome utente SNMPv3 troppo lungo: al massimo 32 caratteri")
	}
	auth, ok := authProtocols[normProto(c.Auth)]
	if !ok {
		return invalid("protocollo di autenticazione SNMPv3 non gestito: scegli SHA, SHA-224, SHA-256, SHA-384, SHA-512 o MD5, oppure nessuno")
	}
	priv, ok := privProtocols[normProto(c.Priv)]
	if !ok {
		return invalid("protocollo di cifratura SNMPv3 non gestito: scegli AES (128 bit) o DES, oppure nessuno")
	}
	if priv != gosnmp.NoPriv && auth == gosnmp.NoAuth {
		return invalid("la cifratura SNMPv3 richiede anche l'autenticazione: scegli un protocollo di autenticazione")
	}
	if err := checkPass(auth != gosnmp.NoAuth, c.AuthPass, "autenticazione"); err != nil {
		return err
	}
	if err := checkPass(priv != gosnmp.NoPriv, c.PrivPass, "cifratura"); err != nil {
		return err
	}
	usm := &gosnmp.UsmSecurityParameters{UserName: c.User, AuthenticationProtocol: auth, PrivacyProtocol: priv}
	g.MsgFlags = gosnmp.NoAuthNoPriv
	if auth != gosnmp.NoAuth {
		g.MsgFlags = gosnmp.AuthNoPriv
		usm.AuthenticationPassphrase = c.AuthPass
	}
	if priv != gosnmp.NoPriv {
		g.MsgFlags = gosnmp.AuthPriv
		usm.PrivacyPassphrase = c.PrivPass
	}
	g.Version = gosnmp.Version3
	g.SecurityModel = gosnmp.UserSecurityModel
	g.SecurityParameters = usm
	return nil
}

// checkPass: le password SNMPv3 devono avere almeno 8 caratteri (RFC 3414,
// 11.2); una password scritta senza scegliere il protocollo è un errore,
// per non usare per sbaglio una sicurezza più debole di quella voluta.
func checkPass(needed bool, pass, what string) *Error {
	switch {
	case needed && pass == "":
		return invalid("manca la password di " + what + " SNMPv3")
	case needed && utf8.RuneCountInString(pass) < 8:
		return invalid("la password di " + what + " SNMPv3 deve avere almeno 8 caratteri")
	case !needed && pass != "":
		return invalid("hai scritto la password di " + what + " SNMPv3 ma non hai scelto il protocollo")
	}
	return nil
}

// warnings segnala le configurazioni che espongono dati o credenziali.
func warnings(g *gosnmp.GoSNMP) []string {
	if g.Version != gosnmp.Version3 {
		return []string{"SNMPv2c trasmette la community in chiaro: chi osserva il traffico può leggerla. Se il dispositivo lo consente, usa SNMPv3 con autenticazione e cifratura."}
	}
	var w []string
	switch g.MsgFlags & gosnmp.AuthPriv {
	case gosnmp.NoAuthNoPriv:
		w = append(w, "SNMPv3 senza autenticazione né cifratura: le risposte non sono protette.")
	case gosnmp.AuthNoPriv:
		w = append(w, "SNMPv3 senza cifratura: i dati letti viaggiano in chiaro sulla rete.")
	}
	if usm, ok := g.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
		if usm.AuthenticationProtocol == gosnmp.MD5 {
			w = append(w, "MD5 è un'autenticazione superata: se il dispositivo lo consente, usa SHA-256 o almeno SHA.")
		}
		if usm.PrivacyProtocol == gosnmp.DES {
			w = append(w, "DES è una cifratura superata: se il dispositivo lo consente, usa AES.")
		}
	}
	return w
}
