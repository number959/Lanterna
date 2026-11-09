//go:build windows

package pcinfo

import (
	"context"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"lanterna/internal/scan"
)

var (
	setupapi                      = windows.NewLazySystemDLL("setupapi.dll")
	procSetupDiGetDevicePropertyW = setupapi.NewProc("SetupDiGetDevicePropertyW")
)

// Chiavi delle proprietà dei dispositivi (DEVPKEY_* di devpkey.h nel SDK di
// Windows: GUID e numero della proprietà).
var (
	devGUID    = windows.DEVPROPGUID{Data1: 0xa45c254e, Data2: 0xdf1c, Data3: 0x4efd, Data4: [8]byte{0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0}}
	statusGUID = windows.DEVPROPGUID{Data1: 0x4340a6c5, Data2: 0x93fa, Data3: 0x4706, Data4: [8]byte{0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7}}
	driverGUID = windows.DEVPROPGUID{Data1: 0xa8b865dd, Data2: 0x2e3d, Data3: 0x4094, Data4: [8]byte{0xad, 0x97, 0xe5, 0x93, 0xa7, 0x0c, 0x75, 0xd6}}
	nameGUID   = windows.DEVPROPGUID{Data1: 0xb725f130, Data2: 0x47ef, Data3: 0x101a, Data4: [8]byte{0xa5, 0xf1, 0x02, 0x60, 0x8c, 0x9e, 0xeb, 0xac}}

	keyName          = windows.DEVPROPKEY{FmtID: nameGUID, PID: 10}   // DEVPKEY_NAME
	keyHardwareIDs   = windows.DEVPROPKEY{FmtID: devGUID, PID: 3}     // DEVPKEY_Device_HardwareIds
	keyService       = windows.DEVPROPKEY{FmtID: devGUID, PID: 6}     // DEVPKEY_Device_Service
	keyClass         = windows.DEVPROPKEY{FmtID: devGUID, PID: 9}     // DEVPKEY_Device_Class
	keyEnumerator    = windows.DEVPROPKEY{FmtID: devGUID, PID: 24}    // DEVPKEY_Device_EnumeratorName
	keyProblemStatus = windows.DEVPROPKEY{FmtID: statusGUID, PID: 12} // DEVPKEY_Device_ProblemStatus
	keyDriverDate    = windows.DEVPROPKEY{FmtID: driverGUID, PID: 2}  // DEVPKEY_Device_DriverDate
	keyDriverVersion = windows.DEVPROPKEY{FmtID: driverGUID, PID: 3}  // DEVPKEY_Device_DriverVersion
	keyDriverInf     = windows.DEVPROPKEY{FmtID: driverGUID, PID: 5}  // DEVPKEY_Device_DriverInfPath
	keyDriverVendor  = windows.DEVPROPKEY{FmtID: driverGUID, PID: 9}  // DEVPKEY_Device_DriverProvider
)

// devProp legge una proprietà di un dispositivo (SetupDiGetDevicePropertyW);
// false se il dispositivo non ce l'ha.
func devProp(set windows.DevInfo, data *windows.DevInfoData, key *windows.DEVPROPKEY) (windows.DEVPROPTYPE, []byte, bool) {
	size := uint32(512)
	for try := 0; try < 3; try++ {
		buf := make([]byte, size)
		var typ windows.DEVPROPTYPE
		var need uint32
		r, _, err := procSetupDiGetDevicePropertyW.Call(uintptr(set), uintptr(unsafe.Pointer(data)), uintptr(unsafe.Pointer(key)),
			uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&need)), 0)
		if r != 0 {
			return typ, buf[:min(need, size)], true
		}
		if err != windows.ERROR_INSUFFICIENT_BUFFER || need <= size || need > 1<<20 {
			return 0, nil, false
		}
		size = need
	}
	return 0, nil, false
}

func devString(set windows.DevInfo, data *windows.DevInfoData, key *windows.DEVPROPKEY) string {
	if typ, b, ok := devProp(set, data, key); ok && typ == windows.DEVPROP_TYPE_STRING {
		return propString(b)
	}
	return ""
}

// readDevices legge i dispositivi presenti (come Gestione dispositivi senza
// "Mostra dispositivi nascosti"). Solo letture: per un utente standard i dati
// sono gli stessi dell'amministratore.
func readDevices(ctx context.Context) (raw []rawDevice, partial bool, err error) {
	set, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return nil, false, err
	}
	defer set.Close()
	files := map[string]string{}
	for i := 0; i < 4096; i++ {
		if ctx.Err() != nil {
			return raw, true, nil
		}
		data, err := set.EnumDeviceInfo(i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			break
		}
		if err != nil {
			continue
		}
		r := rawDevice{
			Name:       devString(set, data, &keyName),
			Class:      devString(set, data, &keyClass),
			Enumerator: devString(set, data, &keyEnumerator),
			Service:    devString(set, data, &keyService),
			Provider:   devString(set, data, &keyDriverVendor),
			Version:    devString(set, data, &keyDriverVersion),
			Inf:        devString(set, data, &keyDriverInf),
		}
		if typ, b, ok := devProp(set, data, &keyHardwareIDs); ok && typ == windows.DEVPROP_TYPE_STRING_LIST {
			r.HardwareIDs = propStringList(b)
		}
		if typ, b, ok := devProp(set, data, &keyDriverDate); ok && typ == windows.DEVPROP_TYPE_FILETIME {
			r.Date = filetimeDate(b)
		}
		// Il codice di problema vale solo se lo stato ha DN_HAS_PROBLEM (cfg.h).
		var status, problem uint32
		if windows.CM_Get_DevNode_Status(&status, &problem, data.DevInst, 0) == nil && status&windows.DN_HAS_PROBLEM != 0 {
			r.Problem = int(problem)
			if typ, b, ok := devProp(set, data, &keyProblemStatus); ok && (typ == windows.DEVPROP_TYPE_NTSTATUS || typ == windows.DEVPROP_TYPE_INT32 || typ == windows.DEVPROP_TYPE_UINT32) {
				r.Status, _ = propUint32(b)
			}
		}
		if r.Service != "" {
			f, seen := files[strings.ToLower(r.Service)]
			if !seen {
				f = serviceFile(r.Service)
				files[strings.ToLower(r.Service)] = f
			}
			r.File = f
		}
		raw = append(raw, r)
	}
	return raw, false, nil
}

// serviceFile legge il file del driver dalla chiave del servizio (ImagePath,
// solo il nome del file).
func serviceFile(service string) string {
	if strings.ContainsAny(service, `\/`) {
		return ""
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+service, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	path, _, _ := k.GetStringValue("ImagePath")
	typ, _, _ := k.GetIntegerValue("Type")
	// Type 1 = driver in kernel, 2 = driver del file system.
	return DriverFile(path, service, typ == 1 || typ == 2)
}

// codeIntegrity legge le opzioni dell'integrità del codice; nil se Windows
// non le comunica.
func codeIntegrity() *scan.CodeIntegrity {
	info := struct{ Length, Options uint32 }{Length: 8}
	if err := windows.NtQuerySystemInformation(windows.SystemCodeIntegrityInformation, unsafe.Pointer(&info), 8, nil); err != nil {
		return nil
	}
	return CodeIntegrityOf(info.Options)
}
