//go:build windows

package winapi

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ICMP tramite IcmpSendEcho (iphlpapi.dll): funziona senza privilegi di
// amministratore, a differenza dei socket raw.

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

type ipOptionInformation struct {
	TTL         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData *byte
}

type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          *byte
	Options       ipOptionInformation
}

const (
	ipSuccess             = 0
	ipDestNetUnreachable  = 11002
	ipDestHostUnreachable = 11003
	ipPacketTooBig        = 11009
	ipReqTimedOut         = 11010
	ipTTLExpiredTransit   = 11013
	ipFlagDF              = 0x2
)

type icmpPinger struct{ h windows.Handle }

// NewPinger apre un handle ICMP.
func NewPinger() (Pinger, error) {
	if err := procIcmpCreateFile.Find(); err != nil {
		return nil, err
	}
	r, _, err := procIcmpCreateFile.Call()
	if windows.Handle(r) == windows.InvalidHandle {
		return nil, fmt.Errorf("IcmpCreateFile: %v", err)
	}
	return &icmpPinger{h: windows.Handle(r)}, nil
}

func (p *icmpPinger) Close() { procIcmpCloseHandle.Call(uintptr(p.h)) }

func (p *icmpPinger) Echo(dst net.IP, ttl, size int, df bool, timeout time.Duration) EchoResult {
	ip4 := dst.To4()
	if ip4 == nil {
		return EchoResult{Status: EchoError, Err: fmt.Errorf("solo IPv4: %v", dst)}
	}
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte('a' + i%23)
	}
	opts := ipOptionInformation{TTL: uint8(ttl)}
	if df {
		opts.Flags = ipFlagDF
	}
	// Buffer allineato a 8 byte: una risposta + dati + spazio per un messaggio di errore ICMP.
	replyLen := int(unsafe.Sizeof(icmpEchoReply{})) + size + 8 + 64
	reply := make([]uint64, (replyLen+7)/8)
	var dataPtr uintptr
	if size > 0 {
		dataPtr = uintptr(unsafe.Pointer(&payload[0]))
	}
	start := time.Now()
	n, _, callErr := procIcmpSendEcho.Call(
		uintptr(p.h),
		uintptr(binary.LittleEndian.Uint32(ip4)),
		dataPtr,
		uintptr(size),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)*8),
		uintptr(timeout.Milliseconds()),
	)
	elapsed := time.Since(start)
	if n == 0 {
		code := uint32(0)
		if e, ok := callErr.(windows.Errno); ok {
			code = uint32(e)
		}
		return classify(code, nil, elapsed, callErr)
	}
	r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
	from := make(net.IP, 4)
	binary.LittleEndian.PutUint32(from, r.Address)
	// Il tempo misurato attorno alla chiamata ha risoluzione sotto il
	// millisecondo, mentre RoundTripTime è arrotondato al ms intero.
	rtt := elapsed
	if rt := time.Duration(r.RoundTripTime) * time.Millisecond; rt > rtt {
		rtt = rt
	}
	return classify(r.Status, from, rtt, nil)
}

func classify(status uint32, from net.IP, rtt time.Duration, err error) EchoResult {
	switch status {
	case ipSuccess:
		if from == nil {
			return EchoResult{Status: EchoError, Err: err}
		}
		return EchoResult{Status: EchoOK, From: from, RTT: rtt}
	case ipTTLExpiredTransit, 11014:
		return EchoResult{Status: EchoTTLExpired, From: from, RTT: rtt}
	case ipReqTimedOut:
		return EchoResult{Status: EchoTimeout}
	case ipPacketTooBig:
		return EchoResult{Status: EchoTooBig, From: from}
	case ipDestNetUnreachable, ipDestHostUnreachable, 11004, 11005:
		return EchoResult{Status: EchoUnreachable, From: from}
	}
	if err == nil {
		err = fmt.Errorf("stato ICMP %d", status)
	}
	return EchoResult{Status: EchoError, Err: err}
}
