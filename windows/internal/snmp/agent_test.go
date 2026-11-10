package snmp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// agent è un finto agente SNMP su 127.0.0.1: risponde a GET, GETNEXT e
// GETBULK da una tabella di OID ordinata e registra cosa gli è stato chiesto.
// In SNMPv2c accetta solo la sua community; con user impostato parla
// SNMPv3 (scoperta del motore, autenticazione e cifratura di gosnmp).
type agent struct {
	conn      *net.UDPConn
	community string
	oids      [][]uint32 // in ordine
	vals      []gosnmp.SnmpPDU

	// Comportamento, da impostare prima di start.
	answerFirst int           // risponde solo alle prime N richieste (0: a tutte)
	silent      bool          // non risponde mai
	delay       time.Duration // attesa prima di ogni risposta
	genErrUnder string        // le richieste sotto questo OID ricevono genErr
	// user è l'utente SNMPv3 dell'agente (nil: solo SNMPv2c). script, se
	// impostato, prepara le risposte SNMPv3 al posto dei dati.
	user   *gosnmp.UsmSecurityParameters
	script func(req *gosnmp.SnmpPacket, n int) *gosnmp.SnmpPacket

	mu          sync.Mutex
	requests    int
	badPackets  int
	communities map[string]int
	asked       []string // OID richiesti
	returned    []string // OID restituiti
	maxReps     uint32
	minGap      time.Duration // pausa minima tra una risposta e la richiesta successiva
	lastSent    time.Time
	salt        uint64
}

// testEngineID è l'identificativo del motore SNMPv3 del finto agente.
const testEngineID = "\x80\x00\x1f\x88\x80polaris-test"

// Contatori di USM (RFC 3414) usati nei rapporti dell'agente.
const (
	unknownEngineIDs = ".1.3.6.1.6.3.15.1.1.4.0"
	unknownUserNames = ".1.3.6.1.6.3.15.1.1.3.0"
	wrongDigests     = ".1.3.6.1.6.3.15.1.1.5.0"
)

func newAgent(t *testing.T, community string, data []gosnmp.SnmpPDU) *agent {
	t.Helper()
	slices.SortFunc(data, func(a, b gosnmp.SnmpPDU) int {
		x, _ := parseOID(a.Name)
		y, _ := parseOID(b.Name)
		return compareOID(x, y)
	})
	a := &agent{community: community, communities: map[string]int{}}
	for _, v := range data {
		o, ok := parseOID(v.Name)
		if !ok {
			t.Fatalf("OID non valido nei dati del test: %q", v.Name)
		}
		v.Name = formatOID(o)
		a.oids = append(a.oids, o)
		a.vals = append(a.vals, v)
	}
	return a
}

// start apre il socket, avvia l'agente e lo rende raggiungibile da Collect:
// solo per la durata del test 127.0.0.1 è un indirizzo ammesso.
func (a *agent) start(t *testing.T) {
	t.Helper()
	if a.user != nil {
		// Chiavi dell'utente ricavate una volta sola per il motore dell'agente.
		a.user.AuthoritativeEngineID = testEngineID
		if err := a.user.InitSecurityKeys(); err != nil {
			t.Fatal(err)
		}
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	a.conn = conn
	done := make(chan struct{})
	go a.serve(done)
	useLoopback(t, uint16(conn.LocalAddr().(*net.UDPAddr).Port))
	t.Cleanup(func() {
		conn.Close()
		<-done
		if a.badPackets > 0 {
			t.Errorf("l'agente non ha capito %d pacchetti", a.badPackets)
		}
	})
}

// useLoopback ammette 127.0.0.1 e la porta indicata per la durata del test.
func useLoopback(t *testing.T, port uint16) {
	oldAllowed, oldPort := allowed, snmpPort
	allowed = func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") }
	snmpPort = port
	t.Cleanup(func() { allowed, snmpPort = oldAllowed, oldPort })
}

func (a *agent) serve(done chan struct{}) {
	defer close(done)
	buf := make([]byte, 65535)
	for {
		n, from, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		out := a.handle(append([]byte(nil), buf[:n]...))
		if out == nil {
			continue
		}
		if a.delay > 0 {
			time.Sleep(a.delay)
		}
		a.mu.Lock()
		a.lastSent = time.Now()
		a.mu.Unlock()
		_, _ = a.conn.WriteToUDP(out, from)
	}
}

func (a *agent) handle(raw []byte) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests++
	if !a.lastSent.IsZero() {
		if gap := time.Since(a.lastSent); a.minGap == 0 || gap < a.minGap {
			a.minGap = gap
		}
	}
	if a.silent || (a.answerFirst > 0 && a.requests > a.answerFirst) {
		return nil
	}
	var req *gosnmp.SnmpPacket
	var err error
	if a.user != nil {
		req, err = (&gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: a.flags(),
			SecurityParameters: a.user.Copy()}).SnmpDecodePacket(raw)
	} else {
		req, err = (&gosnmp.GoSNMP{Version: gosnmp.Version2c}).SnmpDecodePacket(raw)
	}
	if err != nil {
		a.badPackets++
		return nil
	}
	if req.Version != gosnmp.Version3 {
		a.communities[req.Community]++
		if req.Community != a.community {
			return nil // come un agente vero: nessuna risposta, nessun indizio
		}
	}
	for _, v := range req.Variables {
		a.asked = append(a.asked, v.Name)
	}

	var resp *gosnmp.SnmpPacket
	switch {
	case a.script != nil:
		resp = a.script(req, a.requests)
	case req.Version == gosnmp.Version3 && req.PDUType == gosnmp.GetRequest && len(req.Variables) == 0:
		resp = v3Report(req, unknownEngineIDs) // scoperta del motore SNMPv3
	default:
		resp = &gosnmp.SnmpPacket{Version: req.Version, Community: req.Community, PDUType: gosnmp.GetResponse, RequestID: req.RequestID}
		if req.Version == gosnmp.Version3 {
			a.salt++
			sp := a.user.Copy().(*gosnmp.UsmSecurityParameters)
			sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime = 3, 1234
			sp.PrivacyParameters = binary.BigEndian.AppendUint64(nil, a.salt)
			resp.MsgFlags, resp.SecurityModel, resp.SecurityParameters = a.flags(), gosnmp.UserSecurityModel, sp
			resp.MsgID, resp.ContextEngineID, resp.ContextName = req.MsgID, testEngineID, req.ContextName
		}
		if a.genErrUnder != "" && len(req.Variables) > 0 && strings.HasPrefix(req.Variables[0].Name+".", a.genErrUnder+".") {
			resp.Error, resp.ErrorIndex = gosnmp.GenErr, 1
			for _, v := range req.Variables {
				resp.Variables = append(resp.Variables, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.Null})
			}
		} else {
			resp.Variables = a.answer(req)
		}
	}
	if resp == nil {
		return nil
	}
	for _, v := range resp.Variables {
		a.returned = append(a.returned, v.Name)
	}
	out, err := resp.MarshalMsg()
	if err != nil {
		a.badPackets++
		return nil
	}
	return out
}

// flags è il livello di sicurezza dell'utente SNMPv3 dell'agente.
func (a *agent) flags() gosnmp.SnmpV3MsgFlags {
	switch {
	case a.user.PrivacyProtocol > gosnmp.NoPriv:
		return gosnmp.AuthPriv
	case a.user.AuthenticationProtocol > gosnmp.NoAuth:
		return gosnmp.AuthNoPriv
	}
	return gosnmp.NoAuthNoPriv
}

// v3Report prepara un rapporto SNMPv3 non autenticato: è così che gli
// agenti comunicano il proprio motore e rifiutano le credenziali (RFC 3414).
func v3Report(req *gosnmp.SnmpPacket, oid string) *gosnmp.SnmpPacket {
	user := ""
	if usm, ok := req.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
		user = usm.UserName
	}
	return &gosnmp.SnmpPacket{
		Version: gosnmp.Version3, MsgFlags: gosnmp.NoAuthNoPriv, SecurityModel: gosnmp.UserSecurityModel,
		SecurityParameters: &gosnmp.UsmSecurityParameters{AuthoritativeEngineID: testEngineID, AuthoritativeEngineBoots: 3, AuthoritativeEngineTime: 1234, UserName: user},
		ContextEngineID:    testEngineID, PDUType: gosnmp.Report, MsgID: req.MsgID, RequestID: req.RequestID,
		Variables: []gosnmp.SnmpPDU{{Name: oid, Type: gosnmp.Counter32, Value: uint32(1)}},
	}
}

// answer applica le regole di RFC 3416 per GET, GETNEXT e GETBULK.
func (a *agent) answer(req *gosnmp.SnmpPacket) []gosnmp.SnmpPDU {
	var out []gosnmp.SnmpPDU
	switch req.PDUType {
	case gosnmp.GetRequest:
		for _, v := range req.Variables {
			o, _ := parseOID(v.Name)
			if i, ok := slices.BinarySearchFunc(a.oids, o, compareOID); ok {
				out = append(out, a.vals[i])
			} else {
				out = append(out, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchObject})
			}
		}
	case gosnmp.GetNextRequest:
		for _, v := range req.Variables {
			out = append(out, a.next(v.Name))
		}
	case gosnmp.GetBulkRequest:
		a.maxReps = max(a.maxReps, req.MaxRepetitions)
		non := min(int(req.NonRepeaters), len(req.Variables))
		for _, v := range req.Variables[:non] {
			out = append(out, a.next(v.Name))
		}
		cur := make([]string, 0, len(req.Variables)-non)
		for _, v := range req.Variables[non:] {
			cur = append(cur, v.Name)
		}
		for r := 0; r < int(req.MaxRepetitions) && len(cur) > 0; r++ {
			ended := true
			for j := range cur {
				v := a.next(cur[j])
				out = append(out, v)
				cur[j] = v.Name
				ended = ended && v.Type == gosnmp.EndOfMibView
			}
			if ended {
				break
			}
		}
	}
	return out
}

// next restituisce il primo oggetto dopo name, o endOfMibView.
func (a *agent) next(name string) gosnmp.SnmpPDU {
	o, _ := parseOID(name)
	i, found := slices.BinarySearchFunc(a.oids, o, compareOID)
	if found {
		i++
	}
	if i >= len(a.oids) {
		return gosnmp.SnmpPDU{Name: name, Type: gosnmp.EndOfMibView}
	}
	return a.vals[i]
}

func (a *agent) stats() (requests int, asked, returned []string, communities map[string]int, maxReps uint32, minGap time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := map[string]int{}
	for k, v := range a.communities {
		c[k] = v
	}
	return a.requests, slices.Clone(a.asked), slices.Clone(a.returned), c, a.maxReps, a.minGap
}

// Valori per i dati dei test.

func str(oid, s string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: []byte(s)}
}

func raw(oid string, b ...byte) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.OctetString, Value: b}
}

func num(oid string, n int) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: n}
}

func ipv(oid, ip string) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.IPAddress, Value: ip}
}
