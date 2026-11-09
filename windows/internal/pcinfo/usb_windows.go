//go:build windows

package pcinfo

import (
	"context"
	"encoding/binary"
	"strings"

	"golang.org/x/sys/windows"

	"lanterna/internal/scan"
)

// Interfacce dei dispositivi (usbiodef.h) e proprietà (devpkey.h) per
// l'albero USB.
var (
	guidUsbHostController = windows.GUID{Data1: 0x3abf6f2d, Data2: 0x71c4, Data3: 0x462a, Data4: [8]byte{0x8a, 0x92, 0x1e, 0x68, 0x61, 0xe6, 0xaf, 0x27}}
	guidUsbHub            = windows.GUID{Data1: 0xf18a0e88, Data2: 0xc30c, Data3: 0x11d0, Data4: [8]byte{0x88, 0x15, 0x00, 0xa0, 0xc9, 0x06, 0xbe, 0xd8}}
	busDescGUID           = windows.DEVPROPGUID{Data1: 0x540b947e, Data2: 0x8b40, Data3: 0x45bc, Data4: [8]byte{0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2}}

	keyDriverKey = windows.DEVPROPKEY{FmtID: devGUID, PID: 11}    // DEVPKEY_Device_Driver
	keyParent    = windows.DEVPROPKEY{FmtID: statusGUID, PID: 8}  // DEVPKEY_Device_Parent
	keyBusDesc   = windows.DEVPROPKEY{FmtID: busDescGUID, PID: 4} // DEVPKEY_Device_BusReportedDeviceDesc
)

// Richieste agli hub: CTL_CODE(FILE_DEVICE_USB = 0x22, funzione,
// METHOD_BUFFERED, FILE_ANY_ACCESS), funzioni di usbiodef.h. Sono tutte
// letture di dati che l'hub conserva dall'enumerazione: nessuna arriva ai
// dispositivi.
const (
	ioctlUsbNodeInformation     = 0x220408 // USB_GET_NODE_INFORMATION (258)
	ioctlUsbConnectionName      = 0x220414 // USB_GET_NODE_CONNECTION_NAME (261)
	ioctlUsbConnectionDriverKey = 0x220420 // USB_GET_NODE_CONNECTION_DRIVERKEY_NAME (264)
	ioctlUsbConnectionInfoEx    = 0x220448 // USB_GET_NODE_CONNECTION_INFORMATION_EX (274)
	ioctlUsbHubInformationEx    = 0x220454 // USB_GET_HUB_INFORMATION_EX (277)
	ioctlUsbPortConnectorProps  = 0x220458 // USB_GET_PORT_CONNECTOR_PROPERTIES (278)
	ioctlUsbConnectionInfoExV2  = 0x22045C // USB_GET_NODE_CONNECTION_INFORMATION_EX_V2 (279)
)

// usbDevices legge i dispositivi presenti con ciò che serve all'albero.
func usbDevices(ctx context.Context) ([]usbRawDev, error) {
	set, err := windows.SetupDiGetClassDevsEx(nil, "", 0, windows.DIGCF_ALLCLASSES|windows.DIGCF_PRESENT, 0, "")
	if err != nil {
		return nil, err
	}
	defer set.Close()
	var out []usbRawDev
	for i := 0; i < 4096 && ctx.Err() == nil; i++ {
		data, err := set.EnumDeviceInfo(i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			break
		}
		if err != nil {
			continue
		}
		inst, err := set.DeviceInstanceID(data)
		if err != nil || inst == "" {
			continue
		}
		d := usbRawDev{
			Instance:   inst,
			Parent:     devString(set, data, &keyParent),
			Name:       devString(set, data, &keyName),
			Class:      devString(set, data, &keyClass),
			Service:    devString(set, data, &keyService),
			Enumerator: devString(set, data, &keyEnumerator),
			DriverKey:  devString(set, data, &keyDriverKey),
		}
		if strings.EqualFold(d.Enumerator, "USB") {
			d.BusName = devString(set, data, &keyBusDesc)
		}
		var status, problem uint32
		if windows.CM_Get_DevNode_Status(&status, &problem, data.DevInst, 0) == nil && status&windows.DN_HAS_PROBLEM != 0 {
			d.Problem = int(problem)
		}
		out = append(out, d)
	}
	return out, ctx.Err()
}

// openUsb apre un hub per le sole richieste di lettura: prima senza diritti
// (bastano per le richieste FILE_ANY_ACCESS), poi come fa USBView di
// Microsoft.
func openUsb(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err == nil {
		return h, nil
	}
	return windows.CreateFile(p, windows.GENERIC_WRITE, windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
}

// usbIoctl manda una richiesta con lo stesso buffer in ingresso e in uscita
// (METHOD_BUFFERED) e restituisce i byte scritti dall'hub.
func usbIoctl(h windows.Handle, code uint32, buf []byte) ([]byte, bool) {
	var n uint32
	if err := windows.DeviceIoControl(h, code, &buf[0], uint32(len(buf)), &buf[0], uint32(len(buf)), &n, nil); err != nil {
		return nil, false
	}
	return buf[:min(int(n), len(buf))], true
}

// usbPortRequest prepara il buffer di una richiesta su una porta: il numero
// della porta (ConnectionIndex) sta sempre nei primi 4 byte.
func usbPortRequest(size, port int) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b, uint32(port))
	return b
}

// usbPortName legge un nome legato a una porta (chiave del driver o nome
// dell'hub collegato), ingrandendo il buffer se serve.
func usbPortName(h windows.Handle, code uint32, port int) string {
	size := 512
	for try := 0; try < 2; try++ {
		b, ok := usbIoctl(h, code, usbPortRequest(size, port))
		if !ok {
			return ""
		}
		name, need := ParseUsbName(b)
		if need == 0 {
			return name
		}
		if need > 64<<10 {
			return ""
		}
		size = need
	}
	return ""
}

type usbWalker struct {
	ctx     context.Context
	ix      *usbIndex
	seen    map[string]bool
	partial bool
}

// readUsb legge l'albero USB: per ogni controller l'hub radice e, porta per
// porta, i dispositivi e gli hub collegati.
func readUsb(ctx context.Context) *scan.UsbInfo {
	devs, err := usbDevices(ctx)
	if err != nil && len(devs) == 0 {
		return &scan.UsbInfo{Read: "error", Controllers: []scan.UsbController{}}
	}
	w := &usbWalker{ctx: ctx, ix: newUsbIndex(devs), seen: map[string]bool{}, partial: err != nil}
	out := &scan.UsbInfo{Read: "ok", Controllers: []scan.UsbController{}}
	for _, d := range w.ix.ordered {
		if ctx.Err() != nil {
			w.partial = true
			break
		}
		// I controller sono sul bus PCI (o ACPI), mai sul bus USB.
		if !strings.EqualFold(d.Class, "USB") || strings.EqualFold(d.Enumerator, "USB") {
			continue
		}
		// Un controller guasto (codice 10, 43...) non ha l'interfaccia attiva:
		// si riconosce dal driver e si mostra con il suo problema, senza hub.
		if paths, err := windows.CM_Get_Device_Interface_List(d.Instance, &guidUsbHostController, windows.CM_GET_DEVICE_INTERFACE_LIST_PRESENT); err != nil || len(paths) == 0 {
			if d.Problem == 0 || UsbControllerKind(d.Service) == "other" {
				continue
			}
		}
		c := scan.UsbController{Name: DeviceName(d.Name, d.Class, d.Enumerator), Kind: UsbControllerKind(d.Service), Problem: d.Problem}
		for _, ch := range w.ix.children[strings.ToUpper(d.Instance)] {
			paths, err := windows.CM_Get_Device_Interface_List(ch.Instance, &guidUsbHub, windows.CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
			if err == nil && len(paths) > 0 {
				c.Hub = w.hub(paths[0], 0)
				break
			}
		}
		out.Controllers = append(out.Controllers, c)
	}
	out.Partial = w.partial
	// "none" (nessun controller, come in una macchina virtuale) solo se la
	// lettura è finita: altrimenti non si può dire.
	if len(out.Controllers) == 0 && out.Read == "ok" {
		out.Read = "none"
		if out.Partial {
			out.Read = "error"
		}
	}
	return out
}

// hub legge un hub e le sue porte occupate o in errore.
func (w *usbWalker) hub(path string, depth int) *scan.UsbHub {
	key := strings.ToUpper(path)
	if depth > usbMaxTiers || w.seen[key] {
		return nil
	}
	w.seen[key] = true
	h, err := openUsb(path)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(h)
	hub := &scan.UsbHub{Ports: []scan.UsbPort{}}
	if b, ok := usbIoctl(h, ioctlUsbNodeInformation, make([]byte, usbNodeInfoSize)); ok {
		hub.PortCount, hub.BusPowered, _ = ParseUsbNodeInfo(b)
	}
	if b, ok := usbIoctl(h, ioctlUsbHubInformationEx, make([]byte, 128)); ok {
		if kind, highest, ok := ParseUsbHubInfoEx(b); ok {
			hub.Kind = kind
			hub.PortCount = max(hub.PortCount, highest)
		}
	}
	hub.PortCount = min(hub.PortCount, usbMaxPortsPerHub)
	for i := 1; i <= hub.PortCount; i++ {
		if w.ctx.Err() != nil {
			w.partial = true
			break
		}
		if p, ok := w.port(h, i, depth); ok {
			hub.Ports = append(hub.Ports, p)
		}
	}
	return hub
}

// port legge una porta; false se è vuota o non risponde.
func (w *usbWalker) port(h windows.Handle, i, depth int) (scan.UsbPort, bool) {
	b, ok := usbIoctl(h, ioctlUsbConnectionInfoEx, usbPortRequest(usbConnInfoExSize+usbPipeInfoSize*usbConnInfoPipeSlots, i))
	if !ok {
		return scan.UsbPort{}, false
	}
	conn, ok := ParseUsbConn(b)
	if !ok || conn.Status == usbStatusNoDevice {
		return scan.UsbPort{}, false
	}
	p := scan.UsbPort{Index: i, Status: UsbStatusName(conn.Status)}
	var flags uint32
	haveV2 := false
	req := usbPortRequest(usbConnInfoV2Size, i)
	binary.LittleEndian.PutUint32(req[4:], usbConnInfoV2Size)
	binary.LittleEndian.PutUint32(req[8:], usbProtocolsAll)
	if b, ok := usbIoctl(h, ioctlUsbConnectionInfoExV2, req); ok {
		if protocols, f, ok := ParseUsbConnV2(b); ok {
			haveV2, flags = true, f
			usb3 := protocols&usbProtocol300 != 0
			p.Usb3 = &usb3
		}
	}
	if b, ok := usbIoctl(h, ioctlUsbPortConnectorProps, usbPortRequest(512, i)); ok {
		if props, companion, ok := ParseUsbPortProps(b); ok {
			visible := props&usbPortUserVisible != 0
			p.Visible = &visible
			p.TypeC = props&usbPortTypeC != 0
			p.Companion = companion != 0
		}
	}
	raw := w.ix.byKey[strings.ToLower(usbPortName(h, ioctlUsbConnectionDriverKey, i))]
	if conn.VID == 0 && conn.PID == 0 && raw == nil && !conn.IsHub {
		return p, true // porta in errore senza un dispositivo riconosciuto
	}
	dev := &scan.UsbDevice{
		VID: hex4(conn.VID), PID: hex4(conn.PID), USB: UsbVersion(conn.BcdUSB),
		Speed:    UsbSpeedName(conn.Speed, flags, haveV2),
		CanSuper: flags&usbCapableSuper != 0, CanSuperPlus: flags&usbCapablePlus != 0,
		Kind: "other",
	}
	if raw != nil {
		dev.Name = usbDeviceName(raw)
		dev.Problem = raw.Problem
		dev.Kind = UsbKind(w.ix.classesOf(raw), conn.IsHub)
	}
	if conn.IsHub {
		dev.Kind = "hub"
		if name := usbPortName(h, ioctlUsbConnectionName, i); name != "" && !strings.ContainsAny(name, `\/`) {
			dev.Hub = w.hub(`\\.\`+name, depth+1)
		}
	}
	p.Device = dev
	return p, true
}
