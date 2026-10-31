//go:build windows

package survey

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"lanterna/internal/scan"
	"lanterna/internal/winapi"
	"lanterna/internal/wlan"
)

// scanWait: il tempo che una scheda conforme ha per completare WlanScan.
const scanWait = 4 * time.Second

// winRadio è la scheda Wi-Fi collegata all'inizio della misura: il GUID resta
// fisso, così una seconda scheda non mescola le letture.
type winRadio struct {
	s    *winapi.WlanSession
	guid [16]byte
	gw   string
}

func openRadio() (*winRadio, error) {
	s, err := winapi.OpenWlan()
	if err != nil {
		return nil, err
	}
	ifaces, err := s.Interfaces()
	if err != nil {
		s.Close()
		return nil, err
	}
	if len(ifaces) == 0 {
		s.Close()
		return nil, errors.New(scan.NoWifiAdapter)
	}
	for _, it := range ifaces {
		if it.State == wlan.StateConnected {
			return &winRadio{s: s, guid: it.GUID, gw: winapi.InterfaceGateway(it.GUID)}, nil
		}
	}
	s.Close()
	return nil, ErrNotConnected
}

func (w *winRadio) Link() (Link, error) {
	l, err := w.s.Link(w.guid)
	if errors.Is(err, winapi.ErrWlanNotConnected) {
		return Link{}, ErrNotConnected
	}
	if err != nil {
		return Link{}, err
	}
	return Link{SSID: l.SSID, BSSID: strings.ToLower(l.BSSID), RssiDbm: l.RssiDbm, RxKbps: l.RxKbps, TxKbps: l.TxKbps, Phy: wlan.PhyNames[l.PhyType], Channel: l.Channel}, nil
}

func (w *winRadio) Scan(ctx context.Context) error {
	if err := w.s.Scan(w.guid); err != nil {
		return err
	}
	select {
	case <-time.After(scanWait):
	case <-ctx.Done():
	}
	return nil
}

func (w *winRadio) Networks() ([]Seen, error) {
	nets, times, err := w.s.BssList(w.guid)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ages := map[string]int64{}
	for _, t := range times {
		ages[fmt.Sprintf("%s|%d", t.BSSID, t.FreqMhz)] = AgeMs(t.HostTime, now)
	}
	out := make([]Seen, len(nets))
	for i, n := range nets {
		age, ok := ages[fmt.Sprintf("%s|%d", n.BSSID, n.FreqMhz)]
		if !ok {
			age = -1
		}
		out[i] = Seen{Bss: n, AgeMs: age}
	}
	return out, nil
}

func (w *winRadio) Gateway() string { return w.gw }

func (w *winRadio) Close() { w.s.Close() }

// Sample misura il punto in cui si trova il PC con la scheda Wi-Fi collegata.
func Sample(ctx context.Context, opt Options) (*scan.SurveySample, error) {
	if _, err := Room(opt.Room); err != nil {
		return nil, err
	}
	if _, err := Seconds(opt.Seconds); err != nil {
		return nil, err
	}
	r, err := openRadio()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return Run(ctx, r, winapi.NewPinger, opt)
}
