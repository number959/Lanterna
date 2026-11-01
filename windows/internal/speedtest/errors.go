package speedtest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"

	"github.com/gorilla/websocket"
)

var (
	// ErrBusy: Locate ha risposto 204 (nessuna capacità) o 429 (troppe
	// richieste dalla stessa rete), oppure nessun server ha indirizzi validi.
	ErrBusy = errors.New("M-Lab è occupato, riprova più tardi")
	// ErrProxyAuth: il proxy ha risposto 407. Polaris passa al proxy solo
	// le credenziali scritte nel suo indirizzo (autenticazione Basic), non
	// NTLM o Kerberos.
	ErrProxyAuth = errors.New("il proxy chiede un'autenticazione che Polaris non gestisce: chiedi all'amministratore della rete di consentire il test verso measurementlab.net e measurement-lab.org, oppure provalo da un'altra rete")
)

// notReached: il test è fallito prima che M-Lab rispondesse (rete assente,
// nome non risolto): non conta per i limiti di frequenza.
type notReached struct{ error }

func (e notReached) Unwrap() error { return e.error }

// NotReached dice se il test è fallito senza contattare M-Lab: in quel caso
// il tentativo non conta per i limiti (proxy compreso, che ha fermato la
// richiesta prima che arrivasse).
func NotReached(err error) bool {
	var nr notReached
	return errors.As(err, &nr) || errors.Is(err, ErrProxyAuth)
}

// isProxyAuth riconosce il rifiuto 407 del proxy al CONNECT, che net/http e
// gorilla/websocket restituiscono come errore con il testo dello stato.
func isProxyAuth(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "proxy authentication required") || strings.Contains(s, " 407")
}

// noServer: nessun server indicato da Locate ha accettato il download.
func noServer(last error) error {
	if last == nil {
		return ErrBusy
	}
	if errors.Is(last, ErrBusy) {
		return last
	}
	return errors.New("nessun server di M-Lab ha accettato il test: " + describe(last))
}

// describe traduce un errore di rete in una frase breve, senza indirizzi
// IP, porte o nomi: i messaggi finiscono nell'interfaccia e nei rapporti.
func describe(err error) string {
	if err == nil {
		return "errore sconosciuto"
	}
	var hs handshakeError
	if errors.As(err, &hs) {
		return hs.msg
	}
	// Il proxy stesso non risponde: non è un problema di M-Lab.
	if strings.Contains(err.Error(), "proxyconnect") && !isProxyAuth(err) {
		return "il proxy configurato su questo PC non risponde"
	}
	var closeErr *websocket.CloseError
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var netErr net.Error
	switch {
	case errors.Is(err, ErrProxyAuth):
		return ErrProxyAuth.Error()
	case errors.Is(err, context.Canceled):
		return "test interrotto"
	case errors.Is(err, context.DeadlineExceeded):
		return "tempo scaduto"
	case errors.As(err, &closeErr) && !normalEnd(err) && closeErr.Code != websocket.CloseAbnormalClosure:
		// Solo un vero messaggio di chiusura del server: 1006 lo scrive
		// gorilla/websocket quando la connessione cade senza alcun messaggio
		// (nessun server lo invia, RFC 6455 7.4.1) e finisce sotto, tra le
		// connessioni interrotte. Il motivo scritto dal server resta fuori:
		// potrebbe contenere indirizzi.
		return fmt.Sprintf("il server ha chiuso la connessione segnalando un errore, codice %d", closeErr.Code)
	case errors.As(err, &dnsErr):
		return "nome del server non risolto (DNS)"
	case errors.As(err, &certErr), errors.As(err, &unknownCA), errors.As(err, &hostErr):
		return "certificato del server non valido o non attendibile su questo PC (un proxy che ispeziona le connessioni cifrate può causarlo)"
	case errors.Is(err, websocket.ErrBadHandshake):
		return "il server ha rifiutato il test"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connessione rifiutata"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "connessione interrotta"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "tempo scaduto"
	case isProxyAuth(err):
		return ErrProxyAuth.Error()
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "refused"):
		return "connessione rifiutata"
	case strings.Contains(s, "reset") || strings.Contains(s, "forcibly closed") || strings.Contains(s, "eof"):
		return "connessione interrotta"
	case strings.Contains(s, "tls") || strings.Contains(s, "certificate") || strings.Contains(s, "x509"):
		return "errore nella connessione cifrata (TLS)"
	case strings.Contains(s, "proxy"):
		return "il proxy ha rifiutato la connessione"
	case strings.Contains(s, "unreachable") || strings.Contains(s, "no route"):
		return "rete non raggiungibile"
	}
	return "connessione non riuscita"
}

// handshakeError: il server ha risposto alla negoziazione WebSocket con un
// errore HTTP (per esempio 403 per un gettone scaduto, 503 per capacità).
type handshakeError struct{ msg string }

func (e handshakeError) Error() string { return e.msg }
