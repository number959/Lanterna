// Package winapi raccoglie i dati che richiedono le API native di Windows.
// Sugli altri sistemi le funzioni restituiscono ErrUnsupported, così il resto
// del programma (e i test) compila ovunque.
package winapi

import (
	"errors"
	"net"
	"time"
)

var ErrUnsupported = errors.New("misura disponibile solo su Windows")

// EchoStatus è l'esito di una singola richiesta ICMP.
type EchoStatus int

const (
	EchoOK EchoStatus = iota
	EchoTTLExpired
	EchoTimeout
	EchoTooBig
	EchoUnreachable
	EchoError
)

// EchoResult descrive la risposta a un echo ICMP.
type EchoResult struct {
	Status EchoStatus
	From   net.IP
	RTT    time.Duration
	Err    error
}

// Pinger invia echo ICMP; ogni goroutine dovrebbe usarne uno proprio.
type Pinger interface {
	Echo(dst net.IP, ttl, size int, dontFragment bool, timeout time.Duration) EchoResult
	Close()
}
