//go:build windows

package netdisc

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os/exec"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"lanterna/internal/winps"
)

var (
	iphlpapi               = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpForwardTable2 = iphlpapi.NewProc("GetIpForwardTable2")
	procFreeMibTable       = iphlpapi.NewProc("FreeMibTable")
	errNoTable             = errors.New("tabella di instradamento non letta")
)

// Disposizione di MIB_IPFORWARD_ROW2 (netioapi.h): InterfaceLuid (8),
// InterfaceIndex (4), DestinationPrefix (IP_ADDRESS_PREFIX: SOCKADDR_INET di
// 28 byte, lunghezza del prefisso, allineamento a 32), NextHop (SOCKADDR_INET,
// 28), SitePrefixLength (1 + 3), ValidLifetime, PreferredLifetime, Metric,
// Protocol, Loopback/AutoconfigureAddress/Publish/Immortal (4 byte), Age,
// Origin: 104 byte in tutto. La riga si legge campo per campo dalla memoria
// che Windows alloca e libera con FreeMibTable.
const (
	rowSize      = 104
	offDest      = 12 // SOCKADDR_INET: famiglia (2), porta (2), indirizzo IPv4 (4)
	offPrefixLen = 40
	offNextHop   = 44
	offMetric    = 84
	offProtocol  = 88
	offOrigin    = 100
	afInet       = 2
)

// Routes legge le rotte IPv4 verso le altre reti private (GetIpForwardTable2).
func Routes() ([]Route, error) {
	// Windows scrive qui l'indirizzo della tabella, allocata fuori dal garbage
	// collector: la si tiene come unsafe.Pointer, senza conversioni da uintptr.
	var table unsafe.Pointer
	if r, _, _ := procGetIpForwardTable2.Call(afInet, uintptr(unsafe.Pointer(&table))); r != 0 || table == nil {
		return nil, errNoTable
	}
	defer procFreeMibTable.Call(uintptr(table))
	// MIB_IPFORWARD_TABLE2: NumEntries (4), allineamento a 8, poi le righe.
	n := *(*uint32)(table)
	if n > 100000 {
		return nil, errNoTable
	}
	rows := make([]rawRoute, 0, n)
	for i := uint32(0); i < n; i++ {
		b := unsafe.Slice((*byte)(unsafe.Add(table, 8+uintptr(i)*rowSize)), rowSize)
		if binary.LittleEndian.Uint16(b[offDest:]) != afInet {
			continue
		}
		dest := net.IPv4(b[offDest+4], b[offDest+5], b[offDest+6], b[offDest+7])
		var nh net.IP
		if binary.LittleEndian.Uint16(b[offNextHop:]) == afInet {
			nh = net.IPv4(b[offNextHop+4], b[offNextHop+5], b[offNextHop+6], b[offNextHop+7])
		}
		rows = append(rows, rawRoute{
			dest:    dest,
			prefix:  int(b[offPrefixLen]),
			nextHop: nh,
			metric:  binary.LittleEndian.Uint32(b[offMetric:]),
			proto:   binary.LittleEndian.Uint32(b[offProtocol:]),
			origin:  binary.LittleEndian.Uint32(b[offOrigin:]),
		})
	}
	return filterRoutes(rows), nil
}

// adScript legge le sottoreti di Active Directory dalla partizione di
// configurazione (CN=Subnets,CN=Sites): nome e sito, mai la descrizione.
const adScript = `$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try {
  $root = [ADSI]'LDAP://RootDSE'
  $cfg = [string]$root.configurationNamingContext
  if (-not $cfg) { 'NODOMAIN'; exit }
  $s = New-Object System.DirectoryServices.DirectorySearcher
  $s.SearchRoot = [ADSI]('LDAP://CN=Subnets,CN=Sites,' + $cfg)
  $s.Filter = '(objectClass=subnet)'
  $s.PageSize = 500
  $s.SizeLimit = 2000
  $s.ClientTimeout = [TimeSpan]::FromSeconds(15)
  [void]$s.PropertiesToLoad.Add('name')
  [void]$s.PropertiesToLoad.Add('siteObject')
  foreach ($r in $s.FindAll()) {
    $n = [string]$r.Properties['name'][0]
    $site = ''
    if ($r.Properties['siteobject'].Count) { $site = (([string]$r.Properties['siteobject'][0]) -split ',')[0] -replace '^CN=', '' }
    "S` + "`t" + `$n` + "`t" + `$site"
  }
} catch { 'ERR` + "`t" + `' + $_.Exception.HResult }
`

// ADSubnetsOf legge le sottoreti di Active Directory; domain è il dominio del
// PC (vuoto se il PC non è in un dominio, e allora non si interroga nulla).
func ADSubnetsOf(ctx context.Context, domain string) ADSubnets {
	if domain == "" {
		return ADSubnets{Read: "nodomain"}
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	out, err := winps.Command(ctx, adScript).Output()
	if err != nil && len(out) == 0 {
		var ee *exec.Error
		if errors.As(err, &ee) {
			return ADSubnets{Read: "error", Error: "PowerShell non disponibile."}
		}
		if ctx.Err() != nil {
			return ADSubnets{Read: "unreachable", Error: "Il controller di dominio non ha risposto in tempo."}
		}
		return ADSubnets{Read: "error", Error: "Lettura delle sottoreti di Active Directory non riuscita."}
	}
	return parseADOutput(string(out))
}
