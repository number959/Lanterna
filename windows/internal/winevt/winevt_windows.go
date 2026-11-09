//go:build windows

package winevt

import (
	"context"
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wevtapi        = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtQuery   = wevtapi.NewProc("EvtQuery")
	procEvtNext    = wevtapi.NewProc("EvtNext")
	procEvtRender  = wevtapi.NewProc("EvtRender")
	procEvtClose   = wevtapi.NewProc("EvtClose")
	errChannelGone = windows.Errno(15007) // ERROR_EVT_CHANNEL_NOT_FOUND
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryReverseDirection = 0x200
	evtRenderEventXML        = 1
	nextTimeoutMs            = 10000
)

func mapErr(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return ErrDenied
	case errors.Is(err, errChannelGone):
		return ErrNoChannel
	}
	return err
}

// Query legge al massimo max eventi del canale che rispondono
// all'interrogazione XPath, dal più recente. Si ferma quando il contesto
// scade e restituisce quelli già letti.
func Query(ctx context.Context, channel, xpath string, max int) ([]Event, error) {
	if err := procEvtQuery.Find(); err != nil {
		return nil, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ch, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return nil, err
	}
	q, err := windows.UTF16PtrFromString(xpath)
	if err != nil {
		return nil, err
	}
	h, _, callErr := procEvtQuery.Call(0, uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)), evtQueryChannelPath|evtQueryReverseDirection)
	if h == 0 {
		return nil, mapErr(callErr)
	}
	defer procEvtClose.Call(h)
	out := []Event{}
	handles := make([]uintptr, 32)
	buf := make([]uint16, 16384)
	for len(out) < max && ctx.Err() == nil {
		var n uint32
		r, _, callErr := procEvtNext.Call(h, uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), nextTimeoutMs, 0, uintptr(unsafe.Pointer(&n)))
		if r == 0 {
			if errors.Is(callErr, windows.ERROR_NO_MORE_ITEMS) || errors.Is(callErr, windows.ERROR_TIMEOUT) {
				break
			}
			return out, mapErr(callErr)
		}
		for i := 0; i < int(n); i++ {
			ev, err := render(handles[i], &buf)
			procEvtClose.Call(handles[i])
			if err == nil && len(out) < max {
				out = append(out, ev)
			}
		}
	}
	return out, nil
}

func render(h uintptr, buf *[]uint16) (Event, error) {
	for try := 0; try < 2; try++ {
		b := *buf
		var used, props uint32
		r, _, err := procEvtRender.Call(0, h, evtRenderEventXML, uintptr(len(b)*2), uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			n := int(used / 2)
			if n > len(b) {
				n = len(b)
			}
			return ParseXML([]byte(windows.UTF16ToString(b[:n])))
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || used == 0 || used > 1<<22 {
			return Event{}, err
		}
		*buf = make([]uint16, used/2+1)
	}
	return Event{}, errors.New("evento troppo grande")
}
