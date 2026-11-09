//go:build windows

package pcinfo

import (
	"context"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"lanterna/internal/scan"
	"lanterna/internal/winevt"
)

// readMemDiag legge l'esito di Diagnostica memoria Windows dal registro di
// sistema (leggibile anche senza amministratore).
func readMemDiag(ctx context.Context) *scan.MemDiagInfo {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	events, err := winevt.Query(ctx, "System", winevt.XPath(nil, MemDiagDays, MemDiagResults, MemDiagSchedule), 40)
	if err != nil && len(events) == 0 {
		return nil
	}
	return MemDiagFrom(events, MemDiagDays)
}

// readFsChecks legge i controlli del file system degli ultimi EventsDays
// giorni dal registro Applicazione.
func readFsChecks(ctx context.Context) []scan.FsCheck {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	events, err := winevt.Query(ctx, AppChannel, winevt.XPath(nil, EventsDays, FsProviders...), 200)
	if err != nil && len(events) == 0 {
		return nil
	}
	return FsChecksFrom(events)
}

// fsctlIsVolumeDirty è FSCTL_IS_VOLUME_DIRTY (ntifs.h): CTL_CODE(9, 30,
// METHOD_BUFFERED, FILE_ANY_ACCESS).
const fsctlIsVolumeDirty = 0x00090078

// volumeDirty dice se Windows controllerà il volume al prossimo avvio. Il
// volume si apre senza diritti di lettura o scrittura (basta per chiedere lo
// stato); nil se Windows non risponde, per esempio senza amministratore.
func volumeDirty(letter string) *bool {
	if len(letter) != 2 || letter[1] != ':' {
		return nil
	}
	p, err := windows.UTF16PtrFromString(`\\.\` + letter)
	if err != nil {
		return nil
	}
	h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)
	var flags, n uint32
	if err := windows.DeviceIoControl(h, fsctlIsVolumeDirty, nil, 0, (*byte)(unsafe.Pointer(&flags)), 4, &n, nil); err != nil {
		if err == windows.ERROR_FILE_CORRUPT {
			dirty := true
			return &dirty
		}
		return nil
	}
	dirty := flags&1 != 0
	return &dirty
}

// serviceState legge il modo di avvio di un servizio con i soli diritti di
// lettura (golang.org/x/sys/windows/svc/mgr chiede l'accesso completo e
// senza amministratore fallirebbe).
func serviceState(m windows.Handle, name string) *scan.ServiceState {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil
	}
	h, err := windows.OpenService(m, n, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return nil
	}
	defer windows.CloseServiceHandle(h)
	st := &scan.ServiceState{Start: "unknown"}
	var need uint32
	buf := make([]byte, 8192)
	if err := windows.QueryServiceConfig(h, (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0])), uint32(len(buf)), &need); err == nil {
		cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
		switch cfg.StartType {
		case windows.SERVICE_AUTO_START, windows.SERVICE_BOOT_START, windows.SERVICE_SYSTEM_START:
			st.Start = "auto"
			var d windows.SERVICE_DELAYED_AUTO_START_INFO
			if windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (*byte)(unsafe.Pointer(&d)), uint32(unsafe.Sizeof(d)), &need) == nil && d.IsDelayedAutoStartUp != 0 {
				st.Start = "delayed"
			}
		case windows.SERVICE_DEMAND_START:
			st.Start = "manual"
		case windows.SERVICE_DISABLED:
			st.Start = "disabled"
		}
	}
	var status windows.SERVICE_STATUS
	if windows.QueryServiceStatus(h, &status) == nil {
		st.Running = status.CurrentState == windows.SERVICE_RUNNING
	}
	return st
}

// updateServices legge i servizi di Windows Update.
func updateServices() *scan.UpdateService {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil
	}
	defer windows.CloseServiceHandle(m)
	s := &scan.UpdateService{WU: serviceState(m, "wuauserv"), USO: serviceState(m, "UsoSvc"), BITS: serviceState(m, "BITS")}
	if s.WU == nil && s.USO == nil && s.BITS == nil {
		return nil
	}
	return s
}

// updatePolicy legge i criteri di gruppo di Windows Update; dell'eventuale
// server dell'organizzazione conta solo che ci sia, mai l'indirizzo.
func updatePolicy() *scan.UpdatePolicy {
	p := &scan.UpdatePolicy{}
	found := false
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`, registry.QUERY_VALUE); err == nil {
		if v, ok := dword(k, "NoAutoUpdate"); ok {
			p.NoAutoUpdate, found = v == 1, true
		}
		if v, ok := dword(k, "AUOptions"); ok {
			p.AUOptions, found = int(v), true
		}
		if v, ok := dword(k, "UseWUServer"); ok && v == 1 {
			if w, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`, registry.QUERY_VALUE); err == nil {
				if s, _, err := w.GetStringValue("WUServer"); err == nil && strings.TrimSpace(s) != "" {
					p.Managed, found = true, true
				}
				w.Close()
			}
		}
		k.Close()
	}
	if !found {
		return nil
	}
	return p
}
