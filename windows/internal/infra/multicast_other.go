//go:build !windows

package infra

import "net"

// multicastInterface: fuori da Windows l'agente gira solo nei test, dove
// basta il bind all'indirizzo locale.
func multicastInterface(*net.UDPConn, net.IP) {}
