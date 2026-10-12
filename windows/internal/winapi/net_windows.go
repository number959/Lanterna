//go:build windows

package winapi

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"lanterna/internal/scan"
)

const (
	gaaSkipAnycast     = 0x2
	gaaSkipMulticast   = 0x4
	gaaIncludeGateways = 0x80
	adapterDhcpEnabled = 0x4
	ifTypeEthernet     = 6
	ifTypeLoopback     = 24
	ifTypeIEEE80211    = 71
	ifOperStatusUp     = 1
)

var virtualHints = []string{"virtual", "hyper-v", "vmware", "virtualbox", "tap-", "tap ", "wireguard", "wintun", "vpn", "loopback", "bluetooth", "wsl", "docker", "npcap", "zerotier", "tailscale", "teredo", "isatap", "6to4", "pseudo"}

type adapterInfo struct {
	scan.Adapter
	metric uint32
}

// getAdapters chiama GetAdaptersAddresses ingrandendo il buffer se serve.
func getAdapters(family, flags uint32) (*windows.IpAdapterAddresses, error) {
	size := uint32(16 << 10)
	for i := 0; i < 4; i++ {
		buf := make([]byte, size)
		err := windows.GetAdaptersAddresses(family, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			return (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), nil
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, err
		}
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}

// Adapters elenca le schede di rete; quelle con un gateway IPv4 vengono
// prima, ordinate per metrica (la stessa scelta che fa Windows per il traffico).
func Adapters() ([]scan.Adapter, error) {
	const flags = gaaSkipAnycast | gaaSkipMulticast
	first, err := getAdapters(windows.AF_UNSPEC, flags|gaaIncludeGateways)
	var extraGw map[uint32][]string
	if err == windows.ERROR_NOT_SUPPORTED {
		// Alcune implementazioni (Wine) forniscono i gateway solo per AF_INET:
		// indirizzi da una chiamata, gateway IPv4 da una seconda.
		if first, err = getAdapters(windows.AF_UNSPEC, flags); err == nil {
			extraGw = map[uint32][]string{}
			if v4, err4 := getAdapters(windows.AF_INET, flags|gaaIncludeGateways); err4 == nil {
				for a := v4; a != nil; a = a.Next {
					for g := a.FirstGatewayAddress; g != nil; g = g.Next {
						if ip := g.Address.IP(); ip != nil && !ip.IsUnspecified() {
							extraGw[a.IfIndex] = append(extraGw[a.IfIndex], ip.String())
						}
					}
				}
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}
	var list []adapterInfo
	for a := first; a != nil; a = a.Next {
		ad := scan.Adapter{
			Name:        windows.UTF16PtrToString(a.FriendlyName),
			Description: windows.UTF16PtrToString(a.Description),
			Up:          a.OperStatus == ifOperStatusUp,
			IPv4:        []string{},
			IPv6:        []string{},
			Gateways:    []string{},
			DNS:         []string{},
			MTU:         int(a.Mtu),
		}
		if a.Mtu == math.MaxUint32 {
			ad.MTU = 0
		}
		desc := strings.ToLower(ad.Description + " " + ad.Name)
		switch {
		case a.IfType == ifTypeLoopback:
			ad.Kind = "loopback"
		case containsAny(desc, virtualHints):
			ad.Kind = "virtual"
		case a.IfType == ifTypeIEEE80211:
			ad.Kind = "wifi"
		case a.IfType == ifTypeEthernet:
			ad.Kind = "ethernet"
		default:
			ad.Kind = "other"
		}
		if a.PhysicalAddressLength > 0 && a.PhysicalAddressLength <= 8 {
			ad.MAC = net.HardwareAddr(a.PhysicalAddress[:a.PhysicalAddressLength]).String()
		}
		dhcp := a.Flags&adapterDhcpEnabled != 0
		ad.DHCP = &dhcp
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			ip := u.Address.IP()
			if ip == nil {
				continue
			}
			cidr := fmt.Sprintf("%s/%d", ip.String(), u.OnLinkPrefixLength)
			if ip.To4() != nil {
				ad.IPv4 = append(ad.IPv4, cidr)
			} else {
				ad.IPv6 = append(ad.IPv6, cidr)
			}
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := g.Address.IP(); ip != nil && !ip.IsUnspecified() {
				ad.Gateways = append(ad.Gateways, ip.String())
			}
		}
		ad.Gateways = append(ad.Gateways, extraGw[a.IfIndex]...)
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			ip := d.Address.IP()
			// Si escludono i resolver IPv6 "site-local" predefiniti fec0::.
			if ip != nil && !strings.HasPrefix(ip.String(), "fec0:") {
				ad.DNS = append(ad.DNS, ip.String())
			}
		}
		if a.TransmitLinkSpeed > 0 && a.TransmitLinkSpeed != math.MaxUint64 {
			ad.LinkMbps = int64(a.TransmitLinkSpeed / 1_000_000)
		}
		list = append(list, adapterInfo{Adapter: ad, metric: a.Ipv4Metric})
	}
	hasGw4 := func(a adapterInfo) bool {
		for _, g := range a.Gateways {
			if net.ParseIP(g).To4() != nil {
				return a.Up
			}
		}
		return false
	}
	sort.SliceStable(list, func(i, j int) bool {
		gi, gj := hasGw4(list[i]), hasGw4(list[j])
		if gi != gj {
			return gi
		}
		vi, vj := list[i].Kind == "virtual", list[j].Kind == "virtual"
		if vi != vj {
			return !vi
		}
		return list[i].metric < list[j].metric
	})
	out := make([]scan.Adapter, len(list))
	for i, a := range list {
		out[i] = a.Adapter
	}
	return out, nil
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

var procGetIpNetTable = iphlpapi.NewProc("GetIpNetTable")

// Neighbors legge la tabella ARP IPv4 (dispositivi con cui il PC ha
// comunicato di recente), escludendo broadcast e multicast.
func Neighbors() ([]scan.Neighbor, error) {
	if err := procGetIpNetTable.Find(); err != nil {
		return nil, err
	}
	size := uint32(0)
	r, _, _ := procGetIpNetTable.Call(0, uintptr(unsafe.Pointer(&size)), 1)
	if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && r != 0 {
		return nil, fmt.Errorf("GetIpNetTable: %v", windows.Errno(r))
	}
	if size == 0 {
		return []scan.Neighbor{}, nil
	}
	buf := make([]uint32, (size+3)/4)
	r, _, _ = procGetIpNetTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 1)
	if r != 0 {
		return nil, fmt.Errorf("GetIpNetTable: %v", windows.Errno(r))
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), int(size))
	n := int(buf[0])
	out := []scan.Neighbor{}
	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		row := b[4+24*i:]
		if len(row) < 24 {
			break
		}
		typ := u32(row, 20)
		if typ != 3 && typ != 4 { // 3 = dinamico, 4 = statico
			continue
		}
		ml := int(u32(row, 4))
		if ml > 8 {
			ml = 8
		}
		mac := net.HardwareAddr(row[8 : 8+ml])
		ip := net.IPv4(row[16], row[17], row[18], row[19])
		if ip.IsMulticast() || ip.Equal(net.IPv4bcast) || row[19] == 255 || ip.IsUnspecified() {
			continue
		}
		if ml == 0 || mac.String() == "ff:ff:ff:ff:ff:ff" || mac.String() == "00:00:00:00:00:00" {
			continue
		}
		if seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, scan.Neighbor{IP: ip.String(), MAC: mac.String()})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := net.ParseIP(out[i].IP).To4(), net.ParseIP(out[j].IP).To4()
		return string(a) < string(b)
	})
	return out, nil
}
