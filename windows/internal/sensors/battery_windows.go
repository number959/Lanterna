//go:build windows

package sensors

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Interfaccia dei dispositivi batteria (GUID_DEVICE_BATTERY, uguale a
// GUID_DEVCLASS_BATTERY) e codici IOCTL di poclass.h:
// CTL_CODE(FILE_DEVICE_BATTERY = 0x29, funzione, METHOD_BUFFERED, FILE_READ_ACCESS).
var guidDeviceBattery = windows.GUID{Data1: 0x72631e54, Data2: 0x78a4, Data3: 0x11d0, Data4: [8]byte{0xbc, 0xf7, 0x00, 0xaa, 0x00, 0xb7, 0xb3, 0x2a}}

const (
	ioctlBatteryQueryTag         = 0x00294040
	ioctlBatteryQueryInformation = 0x00294044
	ioctlBatteryQueryStatus      = 0x0029404C

	// BATTERY_QUERY_INFORMATION_LEVEL
	batteryInformation = 0
	batteryTemperature = 2
	batteryDeviceName  = 4

	maxBatteries = 4
)

// readBatteries legge lo stato delle batterie con le IOCTL della classe
// batteria, come l'esempio di Microsoft "Enumerating Battery Devices": non
// servono permessi di amministratore.
func readBatteries() []Battery {
	paths, err := windows.CM_Get_Device_Interface_List("", &guidDeviceBattery, windows.CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
	if err != nil {
		return nil
	}
	var out []Battery
	for _, path := range paths {
		if len(out) == maxBatteries {
			break
		}
		if b, ok := readBattery(path); ok {
			out = append(out, b)
		}
	}
	return out
}

func readBattery(path string) (Battery, bool) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Battery{}, false
	}
	var h windows.Handle
	for _, access := range []uint32{windows.GENERIC_READ | windows.GENERIC_WRITE, windows.GENERIC_READ} {
		h, err = windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == nil {
			break
		}
	}
	if err != nil {
		return Battery{}, false
	}
	defer windows.CloseHandle(h)
	ioctl := func(code uint32, in []byte, out []byte) (uint32, bool) {
		var n uint32
		var inp *byte
		if len(in) > 0 {
			inp = &in[0]
		}
		err := windows.DeviceIoControl(h, code, inp, uint32(len(in)), &out[0], uint32(len(out)), &n, nil)
		return n, err == nil
	}
	// Etichetta della batteria: 0 vuol dire nessuna batteria inserita.
	var timeout [4]byte
	tagBuf := make([]byte, 4)
	if n, ok := ioctl(ioctlBatteryQueryTag, timeout[:], tagBuf); !ok || n < 4 {
		return Battery{}, false
	}
	tag := binary.LittleEndian.Uint32(tagBuf)
	if tag == 0 {
		return Battery{}, false
	}
	// BATTERY_QUERY_INFORMATION: BatteryTag, InformationLevel, AtRate.
	query := func(level uint32, out []byte) (uint32, bool) {
		var q [12]byte
		binary.LittleEndian.PutUint32(q[0:], tag)
		binary.LittleEndian.PutUint32(q[4:], level)
		return ioctl(ioctlBatteryQueryInformation, q[:], out)
	}
	info := make([]byte, batteryInfoSize)
	if n, ok := query(batteryInformation, info); !ok || n < batteryInfoSize {
		return Battery{}, false
	}
	var name string
	nameBuf := make([]byte, 512)
	if n, ok := query(batteryDeviceName, nameBuf); ok && n >= 2 {
		name = windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&nameBuf[0])), n/2))
	}
	var temp uint32
	tempBuf := make([]byte, 4)
	if n, ok := query(batteryTemperature, tempBuf); ok && n >= 4 {
		temp = binary.LittleEndian.Uint32(tempBuf)
	}
	// BATTERY_WAIT_STATUS: BatteryTag, Timeout, PowerState, LowCapacity,
	// HighCapacity; tutto a zero tranne l'etichetta per la lettura immediata.
	var ws [20]byte
	binary.LittleEndian.PutUint32(ws[0:], tag)
	status := make([]byte, batteryStatusSize)
	if n, ok := ioctl(ioctlBatteryQueryStatus, ws[:], status); !ok || n < batteryStatusSize {
		return Battery{}, false
	}
	return parseBattery(name, info, status, temp)
}
