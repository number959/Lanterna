//go:build windows

package autoruns

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// readServices elenca servizi e driver con i soli diritti concessi di norma
// a ogni utente: OpenSCManager con SC_MANAGER_CONNECT e
// SC_MANAGER_ENUMERATE_SERVICE (golang.org/x/sys/windows/svc/mgr chiede
// l'accesso completo e senza amministratore fallirebbe), OpenService con
// SERVICE_QUERY_CONFIG e SERVICE_QUERY_STATUS.
func readServices(ctx context.Context, rd reader) sourceResult {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		res := sourceResult{err: fmt.Errorf("Gestione servizi: %w", err)}
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			res.denied = []string{"services", "drivers"}
		}
		return res
	}
	defer windows.CloseServiceHandle(m)
	list, err := enumServices(m)
	if err != nil && len(list) == 0 {
		return sourceResult{err: fmt.Errorf("elenco dei servizi: %w", err)}
	}
	var res sourceResult
	if err != nil {
		res.err = fmt.Errorf("elenco dei servizi incompleto: %w", err)
	}
	denied := false
	var raws []rawService
	for _, s := range list {
		if ctx.Err() != nil {
			// Tempo scaduto: Collect lo dice già, in italiano (Partial).
			break
		}
		// Start resta «sconosciuto» (fuori dai valori 0-4) se la
		// configurazione non si legge: 0 vorrebbe dire «all'avvio del sistema».
		r := rawService{Name: s.name, Display: s.display, Type: s.status.ServiceType, Start: ^uint32(0), Running: s.status.CurrentState == windows.SERVICE_RUNNING}
		if err := serviceConfig(m, &r); err != nil && errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			denied = true
		}
		if f, _, _ := rd.res.Split(r.Image, false); strings.EqualFold(baseOf(f), "svchost.exe") {
			r.ServiceDll = serviceDll(perUserBase(r.Name, r.Type))
		}
		raws = append(raws, r)
	}
	for _, r := range mergeUserServices(raws) {
		res.items = append(res.items, rd.serviceItem(r))
	}
	if denied {
		res.denied = []string{"services"}
	}
	return res
}

type svcEntry struct {
	name, display string
	status        windows.SERVICE_STATUS_PROCESS
}

// enumServices chiama EnumServicesStatusExW (SC_ENUM_PROCESS_INFO,
// SERVICE_WIN32|SERVICE_DRIVER, SERVICE_STATE_ALL) finché restituisce
// ERROR_MORE_DATA, con un buffer di al più 256 KB (il massimo documentato)
// fatto di parole da 8 byte: contiene puntatori e va allineato.
func enumServices(m windows.Handle) ([]svcEntry, error) {
	var out []svcEntry
	var resume uint32
	for round := 0; round < 64; round++ {
		var need, n uint32
		err := windows.EnumServicesStatusEx(m, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32|windows.SERVICE_DRIVER, windows.SERVICE_STATE_ALL, nil, 0, &need, &n, &resume, nil)
		if err == nil {
			return out, nil
		}
		if err != windows.ERROR_MORE_DATA || need == 0 {
			return out, err
		}
		size := min(need, 256*1024)
		buf := make([]uint64, (size+7)/8)
		err = windows.EnumServicesStatusEx(m, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32|windows.SERVICE_DRIVER, windows.SERVICE_STATE_ALL, (*byte)(unsafe.Pointer(&buf[0])), uint32(len(buf)*8), &need, &n, &resume, nil)
		if err != nil && err != windows.ERROR_MORE_DATA {
			return out, err
		}
		if n > 0 {
			entries := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), n)
			for _, e := range entries {
				out = append(out, svcEntry{name: windows.UTF16PtrToString(e.ServiceName), display: windows.UTF16PtrToString(e.DisplayName), status: e.ServiceStatusProcess})
			}
		}
		runtime.KeepAlive(buf)
		if err == nil {
			return out, nil
		}
	}
	return out, errors.New("troppi giri di EnumServicesStatusEx")
}

// serviceConfig legge modo di avvio, riga di comando e account con
// QueryServiceConfigW (8 KB, il massimo documentato, in parole da 8 byte:
// QUERY_SERVICE_CONFIG contiene puntatori e in CI un []byte non allineato
// ha già causato una violazione di accesso) e il ritardo dell'avvio
// automatico con QueryServiceConfig2W.
func serviceConfig(m windows.Handle, r *rawService) error {
	n, err := windows.UTF16PtrFromString(r.Name)
	if err != nil {
		return err
	}
	h, err := windows.OpenService(m, n, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(h)
	buf := make([]uint64, 1024)
	var need uint32
	err = windows.QueryServiceConfig(h, (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0])), uint32(len(buf)*8), &need)
	if err == windows.ERROR_INSUFFICIENT_BUFFER && need > uint32(len(buf)*8) && need <= 64*1024 {
		buf = make([]uint64, (need+7)/8)
		err = windows.QueryServiceConfig(h, (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0])), uint32(len(buf)*8), &need)
	}
	if err != nil {
		return err
	}
	cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	r.Start = cfg.StartType
	r.Type = cfg.ServiceType
	r.Image = windows.UTF16PtrToString(cfg.BinaryPathName)
	r.Account = windows.UTF16PtrToString(cfg.ServiceStartName)
	runtime.KeepAlive(buf)
	if r.Start == windows.SERVICE_AUTO_START {
		var d windows.SERVICE_DELAYED_AUTO_START_INFO
		if windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, (*byte)(unsafe.Pointer(&d)), uint32(unsafe.Sizeof(d)), &need) == nil {
			r.Delayed = d.IsDelayedAutoStartUp != 0
		}
	}
	return nil
}
