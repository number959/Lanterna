//go:build windows

package infra

import (
	"net"
	"syscall"
)

// multicastInterface fissa la scheda di uscita dei pacchetti multicast
// (IP_MULTICAST_IF) sull'indirizzo a cui è legato il socket. Di norma basta
// il bind; l'opzione rende esplicita la scelta quando il PC ha più schede
// (VPN, Hyper-V). Se fallisce decide Windows, come prima.
func multicastInterface(c *net.UDPConn, local net.IP) {
	ip4 := local.To4()
	if ip4 == nil || ip4.IsUnspecified() {
		return
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return
	}
	var a [4]byte
	copy(a[:], ip4)
	_ = rc.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInet4Addr(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, a)
	})
}
