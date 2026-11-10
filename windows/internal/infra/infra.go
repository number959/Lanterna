// Package infra contiene le analisi dell'infrastruttura che contattano altri
// dispositivi della rete: l'inventario della sottorete locale e le verifiche
// di raggiungibilità (isolamento tra zone e servizi critici).
//
// A differenza dell'analisi automatica partono solo su richiesta esplicita
// dell'utente, solo verso indirizzi privati e con un ritmo prudente: nelle
// reti sanitarie ci sono dispositivi medicali che il traffico inatteso può
// rallentare o bloccare. Nessuna funzione esegue scansioni di porte: l'unica
// connessione TCP è quella verso la porta che l'utente indica per una verifica.
// Oltre a ping, NetBIOS e DNS inverso, l'inventario manda solo poche domande
// ai gruppi multicast della rete locale, le stesse che PC e telefoni inviano
// di continuo: una ricerca SSDP e una domanda mDNS, con un secondo giro per i
// tipi di servizio annunciati; i dispositivi rispondono in unicast al PC.
package infra

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/winapi"
)

// Prims sono le operazioni di rete usate dalle analisi, sostituibili nei test.
type Prims struct {
	NewPinger  func() (winapi.Pinger, error)
	Neighbors  func() ([]scan.Neighbor, error)
	LookupAddr func(ctx context.Context, ip string) ([]string, error)
	LookupHost func(ctx context.Context, host string) ([]string, error)
	NetBIOS    func(ctx context.Context, ip net.IP, timeout time.Duration) NBStatus
	// Dial apre una connessione TCP e la chiude subito: restituisce il tempo di apertura.
	Dial func(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error)
	// Multicast apre il socket per interrogare un gruppo multicast
	// ("224.0.0.251:5353" per mDNS, "239.255.255.250:1900" per SSDP)
	// dall'indirizzo IPv4 local della scheda esaminata.
	Multicast func(local net.IP, group string) (MulticastConn, error)
}

// MulticastConn è il socket UDP con cui l'inventario invia una domanda a un
// gruppo multicast e riceve le risposte unicast dei dispositivi.
type MulticastConn interface {
	// Send invia un pacchetto al gruppo.
	Send(b []byte) error
	// Receive attende un pacchetto fino a deadline e ne restituisce la
	// lunghezza e il mittente; alla scadenza l'errore soddisfa
	// errors.Is(err, os.ErrDeadlineExceeded).
	Receive(buf []byte, deadline time.Time) (int, *net.UDPAddr, error)
	Close() error
}

// Native restituisce le operazioni reali del sistema.
func Native() Prims {
	return Prims{
		NewPinger:  winapi.NewPinger,
		Neighbors:  winapi.Neighbors,
		LookupAddr: net.DefaultResolver.LookupAddr,
		LookupHost: net.DefaultResolver.LookupHost,
		NetBIOS:    NetBIOSStatus,
		Multicast:  listenMulticast,
		Dial: func(ctx context.Context, addr string, timeout time.Duration) (time.Duration, error) {
			d := net.Dialer{Timeout: timeout}
			start := time.Now()
			c, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return 0, err
			}
			el := time.Since(start)
			c.Close()
			return el, nil
		},
	}
}

// Options regola il ritmo delle analisi.
type Options struct {
	Interval    time.Duration // pausa minima tra due richieste consecutive
	Workers     int           // richieste contemporanee al massimo
	PingTimeout time.Duration
	DialTimeout time.Duration
	NameTimeout time.Duration // DNS inverso e NetBIOS
	// ListenWindow è l'ascolto delle risposte mDNS e SSDP, in parallelo al
	// giro di ping (0 = valore predefinito, 3 secondi).
	ListenWindow time.Duration
}

// Prudent è il ritmo predefinito: circa 30 richieste al secondo, otto alla
// volta. Una sottorete /24 si esamina in una decina di secondi.
var Prudent = Options{
	Interval:     33 * time.Millisecond,
	Workers:      8,
	PingTimeout:  700 * time.Millisecond,
	DialTimeout:  1500 * time.Millisecond,
	NameTimeout:  900 * time.Millisecond,
	ListenWindow: defaultListen,
}

var privateNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// Private dice se l'indirizzo appartiene a una rete privata (RFC 1918 o ULA IPv6).
func Private(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// RandomMAC dice se il MAC è amministrato localmente (bit 1 del primo
// ottetto): è il caso dei MAC casuali di telefoni e PC e delle schede virtuali.
func RandomMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) > 0 && hw[0]&0x02 != 0
}

// pacer lascia passare una richiesta ogni intervallo, finché il contesto è vivo.
type pacer struct {
	t *time.Ticker
}

func newPacer(d time.Duration) *pacer {
	if d <= 0 {
		d = time.Millisecond
	}
	return &pacer{t: time.NewTicker(d)}
}

func (p *pacer) wait(ctx context.Context) bool {
	select {
	case <-p.t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (p *pacer) stop() { p.t.Stop() }

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// classifyDial distingue una porta che rifiuta (l'host ha risposto con un RST:
// "closed") da una che non risponde affatto ("filtered").
func classifyDial(err error) string {
	if err == nil {
		return "open"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.ECONNREFUSED || errno == 10061) { // 10061 = WSAECONNREFUSED
		return "closed"
	}
	if strings.Contains(strings.ToLower(err.Error()), "refused") {
		return "closed"
	}
	return "filtered"
}
