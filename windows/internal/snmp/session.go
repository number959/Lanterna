package snmp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gosnmp/gosnmp"
)

// snmpPort è la porta dell'agente SNMP. È una variabile solo per i test.
var snmpPort uint16 = 161

// maxOidsPerGet è il numero massimo di oggetti chiesti con una GET.
const maxOidsPerGet = 10

// session è il collegamento con il dispositivo: una richiesta alla volta,
// con la pausa minima tra una risposta e la richiesta successiva.
type session struct {
	ctx      context.Context
	g        *gosnmp.GoSNMP
	opt      Options
	v3       bool
	warnings []string
	last     time.Time   // fine dell'ultima richiesta
	packets  int         // pacchetti inviati, nuovi tentativi compresi
	answered bool        // il dispositivo ha già dato una risposta valida
	unwatch  func() bool // ferma la chiusura del socket all'annullamento di ctx
}

// open prepara gosnmp e apre il socket UDP: per UDP non parte ancora nessun
// pacchetto.
func open(ctx context.Context, ip netip.Addr, cr Creds, opt Options) (*session, *Error) {
	g := &gosnmp.GoSNMP{
		Target:         ip.String(),
		Port:           snmpPort,
		Transport:      "udp",
		Context:        ctx,
		Timeout:        opt.Timeout,
		Retries:        opt.Retries,
		MaxOids:        maxOidsPerGet,
		MaxRepetitions: opt.MaxRepetitions,
	}
	if err := cr.apply(g); err != nil {
		return nil, err
	}
	s := &session{ctx: ctx, g: g, opt: opt, v3: g.Version == gosnmp.Version3, warnings: warnings(g)}
	g.OnSent = func(*gosnmp.GoSNMP) { s.packets++ }
	if err := g.ConnectIPv4(); err != nil {
		e := s.classify(err)
		s.wipe()
		return nil, e
	}
	// gosnmp controlla il contesto solo tra un tentativo e l'altro: chiudere
	// il socket interrompe subito anche l'attesa di una risposta.
	conn := g.Conn
	s.unwatch = context.AfterFunc(ctx, func() { _ = conn.Close() })
	return s, nil
}

// close chiude il socket e cancella le credenziali.
func (s *session) close() {
	if s.unwatch != nil {
		s.unwatch()
	}
	_ = s.g.Close()
	s.wipe()
}

// wipe azzera le chiavi SNMPv3 ricavate dalle password (le copie dei
// pacchetti condividono gli stessi byte) e toglie i riferimenti a community
// e password. Le stringhe di Go non si possono sovrascrivere: restano al
// garbage collector.
func (s *session) wipe() {
	s.g.Community = ""
	if usm, ok := s.g.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok && usm != nil {
		clear(usm.SecretKey)
		clear(usm.PrivacyKey)
		usm.SecretKey, usm.PrivacyKey = nil, nil
		usm.AuthenticationPassphrase, usm.PrivacyPassphrase = "", ""
	}
	s.g.SecurityParameters = nil
}

// pace aspetta che dalla fine della richiesta precedente sia passato
// almeno opt.Interval.
func (s *session) pace() error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.last.IsZero() {
		return nil
	}
	d := s.opt.Interval - time.Since(s.last)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

// tableErr è un errore che riguarda una sola tabella: il dispositivo
// risponde, quindi la lettura prosegue con le altre.
type tableErr string

func (e tableErr) Error() string { return string(e) }

// do esegue una richiesta con il ritmo prudente. Restituisce *Error per gli
// errori che fermano la lettura (nessuna risposta, credenziali, interruzione)
// e tableErr per le risposte non valide.
func (s *session) do(call func() (*gosnmp.SnmpPacket, error)) (*gosnmp.SnmpPacket, error) {
	if err := s.pace(); err != nil {
		return nil, s.classify(err)
	}
	resp, err := call()
	s.last = time.Now()
	if err == nil && resp == nil {
		err = errors.New("risposta vuota")
	}
	if err != nil {
		e := s.classify(err)
		if e.Kind == KindProtocol {
			return nil, tableErr(e.Msg)
		}
		return nil, e
	}
	s.answered = true
	return resp, nil
}

// get legge i valori degli oggetti indicati, al massimo maxOidsPerGet per
// richiesta. Mancano dalla mappa gli oggetti che il dispositivo non ha.
func (s *session) get(oids []string) (map[string]gosnmp.SnmpPDU, error) {
	out := make(map[string]gosnmp.SnmpPDU, len(oids))
	for i := 0; i < len(oids); i += maxOidsPerGet {
		batch := oids[i:min(i+maxOidsPerGet, len(oids))]
		resp, err := s.do(func() (*gosnmp.SnmpPacket, error) { return s.g.Get(batch) })
		if err != nil {
			return out, err
		}
		switch resp.Error {
		case gosnmp.NoError:
		case gosnmp.NoSuchName: // agenti in stile SNMPv1: manca almeno un oggetto del gruppo
			continue
		default:
			return out, tableErr("errore SNMP " + resp.Error.String())
		}
		for _, v := range resp.Variables {
			switch v.Type {
			case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
				continue
			}
			out["."+strings.TrimPrefix(v.Name, ".")] = v
		}
	}
	return out, nil
}

// getNext chiede, per ogni OID, l'oggetto che lo segue (GETNEXT), al massimo
// maxOidsPerGet per richiesta. La mappa ha per chiave l'OID chiesto; mancano
// gli OID dopo i quali il dispositivo non ha altro.
func (s *session) getNext(oids []string) (map[string]gosnmp.SnmpPDU, error) {
	out := make(map[string]gosnmp.SnmpPDU, len(oids))
	for i := 0; i < len(oids); i += maxOidsPerGet {
		batch := oids[i:min(i+maxOidsPerGet, len(oids))]
		resp, err := s.do(func() (*gosnmp.SnmpPacket, error) { return s.g.GetNext(batch) })
		if err != nil {
			return out, err
		}
		switch resp.Error {
		case gosnmp.NoError:
		case gosnmp.NoSuchName: // agenti in stile SNMPv1: fine della vista
			continue
		default:
			return out, tableErr("errore SNMP " + resp.Error.String())
		}
		// Le risposte sono nello stesso ordine delle richieste (RFC 3416).
		for j, v := range resp.Variables[:min(len(resp.Variables), len(batch))] {
			if v.Type != gosnmp.EndOfMibView && v.Type != gosnmp.NoSuchObject && v.Type != gosnmp.NoSuchInstance {
				out[batch[j]] = v
			}
		}
	}
	return out, nil
}

// walk legge il sottoalbero root (di solito una colonna di una tabella) con
// GETBULK, una richiesta alla volta, fino alla fine del sottoalbero o a
// limit righe. fn riceve l'indice della riga (gli identificatori dopo root)
// e il valore. full dice che la tabella aveva altre righe oltre il limite.
func (s *session) walk(root string, limit int, fn func(idx []uint32, v gosnmp.SnmpPDU)) (rows int, full bool, err error) {
	base, ok := parseOID(root)
	if !ok {
		return 0, false, tableErr("OID non valido: " + root)
	}
	cur := root
	var last []uint32
	for {
		reps := s.opt.MaxRepetitions
		if left := limit - rows + 1; left < int(reps) {
			reps = uint32(left) // una riga in più basta per sapere se ce ne sono altre
		}
		resp, err := s.do(func() (*gosnmp.SnmpPacket, error) { return s.g.GetBulk([]string{cur}, 0, reps) })
		if err != nil {
			return rows, false, err
		}
		switch resp.Error {
		case gosnmp.NoError:
		case gosnmp.NoSuchName: // agenti in stile SNMPv1: la tabella non c'è
			return rows, false, nil
		default:
			return rows, false, tableErr("errore SNMP " + resp.Error.String())
		}
		if len(resp.Variables) == 0 {
			return rows, false, nil
		}
		for _, v := range resp.Variables {
			switch v.Type {
			case gosnmp.EndOfMibView, gosnmp.NoSuchObject, gosnmp.NoSuchInstance:
				return rows, false, nil
			}
			oid, ok := parseOID(v.Name)
			if !ok || len(oid) <= len(base) || !hasPrefix(oid, base) {
				return rows, false, nil // fine del sottoalbero: il resto si scarta
			}
			if last != nil && compareOID(oid, last) <= 0 {
				return rows, false, tableErr("il dispositivo ha restituito le righe in ordine errato")
			}
			if rows >= limit {
				return rows, true, nil
			}
			last = oid
			fn(oid[len(base):], v)
			rows++
		}
		cur = formatOID(last)
	}
}

// classify traduce un errore in un messaggio per l'interfaccia, senza
// riportare il testo originale (che contiene indirizzi e porte).
func (s *session) classify(err error) *Error {
	// gosnmp porta la scadenza del socket a quella del contesto: l'attesa può
	// scadere un attimo prima che il contesto risulti scaduto, e gosnmp
	// restituisce allora context.DeadlineExceeded.
	dl, ok := s.ctx.Deadline()
	expired := (ok && !time.Now().Before(dl)) || errors.Is(err, context.DeadlineExceeded)
	if ctxErr := s.ctx.Err(); ctxErr != nil || expired {
		if expired || errors.Is(context.Cause(s.ctx), errDeadline) || errors.Is(ctxErr, context.DeadlineExceeded) {
			return &Error{Kind: KindDeadline, Msg: fmt.Sprintf("tempo massimo della lettura esaurito (%s)", s.opt.Deadline)}
		}
		return &Error{Kind: KindCanceled, Msg: "lettura interrotta"}
	}
	return describe(err, s.v3, s.answered)
}

// describe classifica gli errori di gosnmp e della rete. answered dice che
// il dispositivo aveva già risposto: un'attesa scaduta allora non dipende da
// indirizzo o credenziali.
func describe(err error, v3, answered bool) *Error {
	msg := strings.ToLower(err.Error())
	var errno syscall.Errno
	isErrno := errors.As(err, &errno)
	var nerr net.Error
	switch {
	case errors.Is(err, gosnmp.ErrUnknownUsername):
		return &Error{Kind: KindAuth, Msg: "il dispositivo non conosce questo utente SNMPv3"}
	case errors.Is(err, gosnmp.ErrWrongDigest):
		return &Error{Kind: KindAuth, Msg: "password di autenticazione SNMPv3 errata, o protocollo di autenticazione diverso da quello del dispositivo"}
	case errors.Is(err, gosnmp.ErrDecryption):
		return &Error{Kind: KindAuth, Msg: "password di cifratura SNMPv3 errata, o protocollo di cifratura diverso da quello del dispositivo"}
	case errors.Is(err, gosnmp.ErrUnknownSecurityLevel):
		return &Error{Kind: KindAuth, Msg: "il dispositivo non accetta questo livello di sicurezza per l'utente: controlla se richiede autenticazione e cifratura"}
	case strings.Contains(msg, "not authentic"):
		// Il dispositivo rifiuta le credenziali con un rapporto non
		// autenticato, che gosnmp scarta.
		return &Error{Kind: KindAuth, Msg: "il dispositivo ha risposto ma ha rifiutato le credenziali: nome utente, password o protocollo di autenticazione errati"}
	case errors.Is(err, gosnmp.ErrNotInTimeWindow), errors.Is(err, gosnmp.ErrUnknownEngineID), strings.Contains(msg, "engine id"):
		return &Error{Kind: KindProtocol, Msg: "scambio iniziale SNMPv3 non riuscito (identificativo o orologio del motore SNMP)"}
	case errors.Is(err, gosnmp.ErrUnknownSecurityModels), errors.Is(err, gosnmp.ErrInvalidMsgs), errors.Is(err, gosnmp.ErrUnknownPDUHandlers), errors.Is(err, gosnmp.ErrUnknownReportPDU):
		return &Error{Kind: KindProtocol, Msg: "il dispositivo ha rifiutato il messaggio SNMPv3"}
	// 10061 = WSAECONNREFUSED, 10054 = WSAECONNRESET: su Windows è la porta
	// UDP chiusa, se il sistema la segnala.
	case isErrno && (errno == syscall.ECONNREFUSED || errno == 10061 || errno == 10054), strings.Contains(msg, "refused"):
		return &Error{Kind: KindRefused, Msg: "il dispositivo ha rifiutato la richiesta: il servizio SNMP non è attivo su questo indirizzo (porta UDP 161 chiusa)"}
	// 10051 = WSAENETUNREACH, 10065 = WSAEHOSTUNREACH.
	case isErrno && (errno == syscall.ENETUNREACH || errno == syscall.EHOSTUNREACH || errno == 10051 || errno == 10065),
		strings.Contains(msg, "unreachable"), strings.Contains(msg, "no route"):
		return &Error{Kind: KindUnreachable, Msg: "indirizzo non raggiungibile da questo PC: controlla il collegamento e il gateway"}
	case errors.Is(err, gosnmp.ErrMaxRetriesExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &nerr) && nerr.Timeout(), strings.Contains(msg, "timeout"):
		switch {
		case answered:
			return &Error{Kind: KindTimeout, Msg: "il dispositivo ha smesso di rispondere (può limitare le richieste SNMP o essere sovraccarico)"}
		case v3:
			return &Error{Kind: KindTimeout, Msg: "nessuna risposta: indirizzo, filtro SNMP o SNMPv3 non attivo sul dispositivo"}
		}
		return &Error{Kind: KindTimeout, Msg: "nessuna risposta: indirizzo, community o filtro SNMP"}
	}
	return &Error{Kind: KindProtocol, Msg: "risposta SNMP non valida o errore SNMP non previsto"}
}

// parseOID legge ".1.3.6.1" (il punto iniziale è facoltativo).
func parseOID(s string) ([]uint32, bool) {
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		return nil, false
	}
	parts := strings.Split(s, ".")
	out := make([]uint32, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, false
		}
		out[i] = uint32(v)
	}
	return out, true
}

func formatOID(o []uint32) string {
	var b strings.Builder
	for _, v := range o {
		b.WriteByte('.')
		b.WriteString(strconv.FormatUint(uint64(v), 10))
	}
	return b.String()
}

// compareOID confronta due OID come fanno gli agenti SNMP: numero per
// numero, e a parità di prefisso il più corto viene prima.
func compareOID(a, b []uint32) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

func hasPrefix(o, p []uint32) bool {
	if len(o) < len(p) {
		return false
	}
	for i := range p {
		if o[i] != p[i] {
			return false
		}
	}
	return true
}
