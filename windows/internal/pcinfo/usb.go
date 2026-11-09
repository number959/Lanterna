package pcinfo

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

// Albero dei dispositivi USB (come UsbTreeView). Le strutture delle
// richieste agli hub (usbioctl.h, usbspec.h del Windows SDK) sono
// impacchettate a 1 byte (pshpack1.h): qui si leggono campo per campo da un
// buffer di byte, senza sovrapporre strutture Go, che avrebbero un altro
// allineamento. Offset e valori dalle intestazioni e da Microsoft Learn
// (pagine di usbioctl.h e usbspec.h, verificate il 9/11/2026).

// usbTimeout è il tempo massimo per leggere l'albero USB.
const usbTimeout = 10 * time.Second

const (
	usbNodeInfoSize   = 76 // USB_NODE_INFORMATION (tipo, descrittore dell'hub, alimentazione)
	usbHubInfoExMin   = 6  // USB_HUB_INFORMATION_EX fino a HighestPortNumber
	usbConnInfoExSize = 35 // USB_NODE_CONNECTION_INFORMATION_EX senza PipeList
	usbPipeInfoSize   = 11 // USB_PIPE_INFO: descrittore dell'endpoint (7) + ScheduleOffset (4)
	usbConnInfoV2Size = 16 // USB_NODE_CONNECTION_INFORMATION_EX_V2
	usbPortPropsMin   = 16 // USB_PORT_CONNECTOR_PROPERTIES fino a CompanionPortNumber
	usbNameHeader     = 8  // ConnectionIndex + ActualLength, poi il nome in UTF-16
)

// Bit di USB_PROTOCOLS, USB_NODE_CONNECTION_INFORMATION_EX_V2_FLAGS e
// USB_PORT_PROPERTIES.
const (
	usbProtocol300       = 0x4 // la porta supporta SuperSpeed (USB 3)
	usbProtocolsAll      = 0x7 // Usb110 | Usb200 | Usb300: quelli che Polaris capisce
	usbOperatingSuper    = 0x1 // DeviceIsOperatingAtSuperSpeedOrHigher
	usbCapableSuper      = 0x2 // DeviceIsSuperSpeedCapableOrHigher
	usbOperatingPlus     = 0x4 // DeviceIsOperatingAtSuperSpeedPlusOrHigher
	usbCapablePlus       = 0x8 // DeviceIsSuperSpeedPlusCapableOrHigher
	usbPortUserVisible   = 0x1 // PortIsUserConnectable
	usbPortTypeC         = 0x8 // PortConnectorIsTypeC
	usbStatusNoDevice    = 0   // NoDeviceConnected
	usbStatusConnected   = 1   // DeviceConnected
	usbMaxTiers          = 7   // la specifica USB ammette 5 hub in cascata più la radice
	usbMaxPortsPerHub    = 255 // bNumberOfPorts è un byte
	usbConnInfoPipeSlots = 64
)

// usbConn è ciò che serve di USB_NODE_CONNECTION_INFORMATION_EX.
type usbConn struct {
	Status uint32
	Speed  byte
	IsHub  bool
	VID    uint16
	PID    uint16
	BcdUSB uint16
}

// ParseUsbConn legge USB_NODE_CONNECTION_INFORMATION_EX: descrittore del
// dispositivo da 4 a 21, Speed a 23, DeviceIsHub a 24, ConnectionStatus a 31.
func ParseUsbConn(b []byte) (usbConn, bool) {
	if len(b) < usbConnInfoExSize {
		return usbConn{}, false
	}
	le := binary.LittleEndian
	return usbConn{
		BcdUSB: le.Uint16(b[6:]),
		VID:    le.Uint16(b[12:]),
		PID:    le.Uint16(b[14:]),
		Speed:  b[23],
		IsHub:  b[24] != 0,
		Status: le.Uint32(b[31:]),
	}, true
}

// ParseUsbNodeInfo legge USB_NODE_INFORMATION: per un hub (NodeType 0) il
// numero di porte del descrittore (byte 6) e se è alimentato dal bus (75).
func ParseUsbNodeInfo(b []byte) (ports int, busPowered, ok bool) {
	if len(b) < usbNodeInfoSize || binary.LittleEndian.Uint32(b) != 0 {
		return 0, false, false
	}
	return int(b[6]), b[75] != 0, true
}

// ParseUsbHubInfoEx legge USB_HUB_INFORMATION_EX (da Windows 8): tipo di hub
// e numero più alto di porta.
func ParseUsbHubInfoEx(b []byte) (kind string, highest int, ok bool) {
	if len(b) < usbHubInfoExMin {
		return "", 0, false
	}
	switch binary.LittleEndian.Uint32(b) {
	case 1:
		kind = "root"
	case 2:
		kind = "usb2"
	case 3:
		kind = "usb3"
	}
	return kind, int(binary.LittleEndian.Uint16(b[4:])), true
}

// ParseUsbConnV2 legge USB_NODE_CONNECTION_INFORMATION_EX_V2: protocolli
// della porta e bit della velocità del dispositivo.
func ParseUsbConnV2(b []byte) (protocols, flags uint32, ok bool) {
	if len(b) < usbConnInfoV2Size {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(b[8:]), binary.LittleEndian.Uint32(b[12:]), true
}

// ParseUsbPortProps legge USB_PORT_CONNECTOR_PROPERTIES: proprietà della
// porta e numero della porta compagna (0 se non c'è).
func ParseUsbPortProps(b []byte) (props uint32, companion uint16, ok bool) {
	if len(b) < usbPortPropsMin {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(b[8:]), binary.LittleEndian.Uint16(b[14:]), true
}

// ParseUsbName legge la risposta di IOCTL_USB_GET_NODE_CONNECTION_NAME e
// IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME: ActualLength (byte 4) è la
// lunghezza dell'intera struttura, il nome UTF-16 parte dal byte 8. need è
// la dimensione da chiedere se il buffer non bastava.
func ParseUsbName(b []byte) (name string, need int) {
	if len(b) < usbNameHeader {
		return "", 0
	}
	actual := int(binary.LittleEndian.Uint32(b[4:]))
	if actual > len(b) {
		return "", actual
	}
	end := len(b)
	if actual >= usbNameHeader {
		end = actual
	}
	u := make([]uint16, 0, (end-usbNameHeader)/2)
	for i := usbNameHeader; i+1 < end; i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u)), 0
}

// UsbStatusName traduce USB_CONNECTION_STATUS; "" per una porta vuota.
func UsbStatusName(s uint32) string {
	switch s {
	case usbStatusNoDevice:
		return ""
	case usbStatusConnected:
		return "ok"
	case 2:
		return "failed-enumeration"
	case 3:
		return "general-failure"
	case 4:
		return "overcurrent"
	case 5:
		return "not-enough-power"
	case 6:
		return "not-enough-bandwidth"
	case 7:
		return "nested-too-deeply"
	case 8:
		return "legacy-hub"
	case 9:
		return "enumerating"
	case 10:
		return "reset"
	}
	return "unknown"
}

// UsbSpeedName dà la velocità a cui il dispositivo sta funzionando. Speed
// (USB_DEVICE_SPEED) arriva al massimo a High Speed: SuperSpeed e oltre si
// leggono dai bit della V2, come fa USBView di Microsoft.
func UsbSpeedName(speed byte, flags uint32, haveV2 bool) string {
	if haveV2 {
		if flags&usbOperatingPlus != 0 {
			return "super-plus"
		}
		if flags&usbOperatingSuper != 0 {
			return "super"
		}
	}
	switch speed {
	case 0:
		return "low"
	case 1:
		return "full"
	case 2:
		return "high"
	case 3:
		return "super"
	}
	return ""
}

// UsbVersion scrive bcdUSB come versione: 0x0320 → "3.20".
func UsbVersion(bcd uint16) string {
	if bcd == 0 {
		return ""
	}
	return fmt.Sprintf("%x.%02x", bcd>>8, bcd&0xff)
}

// UsbControllerKind riconosce il tipo di controller dal suo driver di
// Windows.
func UsbControllerKind(service string) string {
	switch strings.ToLower(service) {
	case "usbxhci":
		return "xhci"
	case "usbehci":
		return "ehci"
	case "usbohci":
		return "ohci"
	case "usbuhci":
		return "uhci"
	}
	return "other"
}

// usbKinds: classi di installazione di Windows che dicono che cosa fa un
// dispositivo USB, in ordine di priorità (una webcam ha anche il
// microfono, una cuffia anche i tasti del volume, un multifunzione anche lo
// scanner).
var usbKinds = []struct {
	kind    string
	classes []string
}{
	{"storage", []string{"diskdrive", "cdrom"}},
	{"phone", []string{"wpd", "androidusbdeviceclass"}},
	{"printer", []string{"printer"}},
	{"network", []string{"net"}},
	{"camera", []string{"camera", "image"}},
	{"audio", []string{"media", "audioendpoint"}},
	{"bluetooth", []string{"bluetooth"}},
	{"smartcard", []string{"smartcardreader"}},
	{"input", []string{"keyboard", "mouse", "hidclass", "xnacomposite"}},
	{"serial", []string{"ports", "modem"}},
}

// UsbKind sceglie il tipo di dispositivo dalle classi sue e delle sue
// funzioni (i dispositivi figli in Gestione dispositivi).
func UsbKind(classes []string, isHub bool) string {
	if isHub {
		return "hub"
	}
	have := map[string]bool{}
	for _, c := range classes {
		have[strings.ToLower(strings.TrimSpace(c))] = true
	}
	for _, k := range usbKinds {
		for _, c := range k.classes {
			if have[c] {
				return k.kind
			}
		}
	}
	return "other"
}

// usbRawDev è un dispositivo di Windows come serve all'albero USB. Instance
// e Parent (identificativi di istanza, che per l'USB contengono il numero di
// serie) restano nell'agente: servono solo a collegare i nodi.
type usbRawDev struct {
	Instance   string
	Parent     string
	Name       string
	BusName    string // nome del prodotto riportato dal dispositivo
	Class      string
	Service    string
	Enumerator string
	DriverKey  string
	Problem    int
}

// usbIndex collega i dispositivi tra loro: per chiave del driver (quella
// che l'hub restituisce per ogni porta) e per genitore.
type usbIndex struct {
	byKey    map[string]*usbRawDev
	byInst   map[string]*usbRawDev
	children map[string][]*usbRawDev
	ordered  []*usbRawDev
}

func newUsbIndex(devs []usbRawDev) *usbIndex {
	ix := &usbIndex{byKey: map[string]*usbRawDev{}, byInst: map[string]*usbRawDev{}, children: map[string][]*usbRawDev{}}
	for i := range devs {
		d := &devs[i]
		ix.ordered = append(ix.ordered, d)
		if d.Instance != "" {
			ix.byInst[strings.ToUpper(d.Instance)] = d
		}
		if d.DriverKey != "" {
			ix.byKey[strings.ToLower(d.DriverKey)] = d
		}
		if d.Parent != "" {
			p := strings.ToUpper(d.Parent)
			ix.children[p] = append(ix.children[p], d)
		}
	}
	// Ordine stabile: i controller per nome, i figli per istanza.
	sort.SliceStable(ix.ordered, func(a, b int) bool { return ix.ordered[a].Name < ix.ordered[b].Name })
	for k := range ix.children {
		c := ix.children[k]
		sort.SliceStable(c, func(a, b int) bool { return c[a].Instance < c[b].Instance })
	}
	return ix
}

// classesOf raccoglie la classe del dispositivo e quelle delle sue funzioni
// fino a tre livelli (una chiavetta: dispositivo USB → disco).
func (ix *usbIndex) classesOf(d *usbRawDev) []string {
	out := []string{d.Class}
	level := []*usbRawDev{d}
	for depth := 0; depth < 3 && len(level) > 0; depth++ {
		var next []*usbRawDev
		for _, x := range level {
			for _, c := range ix.children[strings.ToUpper(x.Instance)] {
				out = append(out, c.Class)
				next = append(next, c)
			}
		}
		level = next
	}
	return out
}

// usbDeviceName sceglie il nome da mostrare: quello del prodotto riportato
// dal dispositivo, poi quello di Windows, con le regole di riservatezza di
// Gestione dispositivi (DeviceName).
func usbDeviceName(d *usbRawDev) string {
	name := strings.TrimSpace(d.BusName)
	if name == "" {
		name = d.Name
	}
	return DeviceName(name, d.Class, d.Enumerator)
}

// hex4 scrive VID e PID come nei codici hardware (4 cifre maiuscole).
func hex4(v uint16) string { return fmt.Sprintf("%04X", v) }
