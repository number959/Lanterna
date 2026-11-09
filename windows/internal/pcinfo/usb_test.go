package pcinfo

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// Buffer costruiti a mano con la disposizione impacchettata a 1 byte delle
// strutture di usbioctl.h.

func TestParseUsbConn(t *testing.T) {
	b := make([]byte, usbConnInfoExSize+usbPipeInfoSize*2)
	le := binary.LittleEndian
	le.PutUint32(b[0:], 3)       // ConnectionIndex
	b[4], b[5] = 18, 1           // bLength, bDescriptorType
	le.PutUint16(b[6:], 0x0320)  // bcdUSB
	le.PutUint16(b[12:], 0x0781) // idVendor
	le.PutUint16(b[14:], 0x5583) // idProduct
	b[22], b[23], b[24] = 1, 2, 0
	le.PutUint16(b[25:], 5)
	le.PutUint32(b[27:], 2)
	le.PutUint32(b[31:], 1) // DeviceConnected
	c, ok := ParseUsbConn(b)
	if !ok || c.VID != 0x0781 || c.PID != 0x5583 || c.BcdUSB != 0x0320 || c.Speed != 2 || c.IsHub || c.Status != 1 {
		t.Fatalf("%+v %v", c, ok)
	}
	if _, ok := ParseUsbConn(b[:34]); ok {
		t.Error("buffer corto accettato")
	}
	if hex4(c.VID) != "0781" || UsbVersion(c.BcdUSB) != "3.20" || UsbVersion(0x0200) != "2.00" || UsbVersion(0x0110) != "1.10" || UsbVersion(0) != "" {
		t.Error("VID o versione")
	}
}

func TestParseUsbHub(t *testing.T) {
	n := make([]byte, usbNodeInfoSize)
	n[6], n[75] = 4, 1
	ports, bus, ok := ParseUsbNodeInfo(n)
	if !ok || ports != 4 || !bus {
		t.Fatalf("%d %v %v", ports, bus, ok)
	}
	binary.LittleEndian.PutUint32(n, 1) // UsbMIParent: non è un hub
	if _, _, ok := ParseUsbNodeInfo(n); ok {
		t.Error("nodo composito letto come hub")
	}
	x := make([]byte, 77)
	binary.LittleEndian.PutUint32(x, 3)
	binary.LittleEndian.PutUint16(x[4:], 26)
	kind, high, ok := ParseUsbHubInfoEx(x)
	if !ok || kind != "usb3" || high != 26 {
		t.Fatalf("%q %d %v", kind, high, ok)
	}
	binary.LittleEndian.PutUint32(x, 1)
	if kind, _, _ := ParseUsbHubInfoEx(x); kind != "root" {
		t.Error(kind)
	}
}

func TestParseUsbV2AndPort(t *testing.T) {
	v := make([]byte, usbConnInfoV2Size)
	binary.LittleEndian.PutUint32(v[8:], 0x3)  // Usb110 | Usb200: porta USB 2
	binary.LittleEndian.PutUint32(v[12:], 0x2) // capace di SuperSpeed, non in uso
	pr, fl, ok := ParseUsbConnV2(v)
	if !ok || pr&usbProtocol300 != 0 || fl != usbCapableSuper {
		t.Fatalf("%x %x %v", pr, fl, ok)
	}
	p := make([]byte, 64)
	binary.LittleEndian.PutUint32(p[8:], usbPortUserVisible|usbPortTypeC)
	binary.LittleEndian.PutUint16(p[14:], 17)
	props, comp, ok := ParseUsbPortProps(p)
	if !ok || props&usbPortTypeC == 0 || comp != 17 {
		t.Fatalf("%x %d %v", props, comp, ok)
	}
}

func TestUsbSpeedAndStatus(t *testing.T) {
	cases := []struct {
		speed byte
		flags uint32
		v2    bool
		want  string
	}{
		{2, usbOperatingSuper, true, "super"},
		{2, usbOperatingSuper | usbOperatingPlus, true, "super-plus"},
		{2, usbCapableSuper, true, "high"},
		{2, usbOperatingSuper, false, "high"},
		{3, 0, false, "super"},
		{1, 0, true, "full"},
		{0, 0, false, "low"},
		{9, 0, false, ""},
	}
	for _, c := range cases {
		if got := UsbSpeedName(c.speed, c.flags, c.v2); got != c.want {
			t.Errorf("%d %x %v: %q", c.speed, c.flags, c.v2, got)
		}
	}
	for code, want := range map[uint32]string{0: "", 1: "ok", 2: "failed-enumeration", 4: "overcurrent", 5: "not-enough-power", 7: "nested-too-deeply", 10: "reset", 42: "unknown"} {
		if got := UsbStatusName(code); got != want {
			t.Errorf("%d: %q", code, got)
		}
	}
	if UsbControllerKind("USBXHCI") != "xhci" || UsbControllerKind("usbehci") != "ehci" || UsbControllerKind("") != "other" {
		t.Error("tipo di controller")
	}
}

func TestParseUsbName(t *testing.T) {
	key := `{36fc9e60-c465-11cf-8056-444553540000}\0012`
	u := utf16.Encode([]rune(key))
	b := make([]byte, 512)
	binary.LittleEndian.PutUint32(b[4:], uint32(usbNameHeader+2*len(u)+2))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[usbNameHeader+2*i:], c)
	}
	if name, need := ParseUsbName(b); name != key || need != 0 {
		t.Fatalf("%q %d", name, need)
	}
	binary.LittleEndian.PutUint32(b[4:], 2000)
	if name, need := ParseUsbName(b); name != "" || need != 2000 {
		t.Fatalf("buffer insufficiente: %q %d", name, need)
	}
	if name, _ := ParseUsbName(b[:4]); name != "" {
		t.Error(name)
	}
}

func TestUsbKindAndIndex(t *testing.T) {
	cases := map[string][]string{
		"storage":   {"USB", "DiskDrive"},
		"phone":     {"USB", "WPD", "Image"},
		"camera":    {"USB", "Camera", "MEDIA"},
		"audio":     {"USB", "MEDIA", "HIDClass"},
		"input":     {"HIDClass", "Keyboard", "Mouse"},
		"smartcard": {"USB", "SmartCardReader", "HIDClass"},
		"printer":   {"USB", "Printer", "Image"},
		"network":   {"Net"},
		"other":     {"USB"},
	}
	for want, classes := range cases {
		if got := UsbKind(classes, false); got != want {
			t.Errorf("%v: %q", classes, got)
		}
	}
	if UsbKind([]string{"USB"}, true) != "hub" {
		t.Error("hub")
	}
	ix := newUsbIndex([]usbRawDev{
		{Instance: `USB\VID_0781&PID_5583\4C530001`, Parent: `USB\ROOT_HUB30\4&1`, Name: "Dispositivo di archiviazione di massa USB", BusName: "Ultra Fit", Class: "USB", Enumerator: "USB", DriverKey: `{36FC9E60-C465-11CF-8056-444553540000}\0012`},
		{Instance: `USBSTOR\DISK&VEN_SANDISK\4C530001&0`, Parent: `USB\VID_0781&PID_5583\4C530001`, Name: "SanDisk Ultra Fit USB Device", Class: "DiskDrive", Enumerator: "USBSTOR"},
		{Instance: `USB\VID_04E8&PID_6860\R58N`, Name: "Galaxy di Mario", BusName: "SAMSUNG_Android", Class: "WPD", Enumerator: "USB", DriverKey: `{EEC5AD98-8080-425F-922A-DABF3DE3F69A}\0003`},
	})
	d := ix.byKey[`{36fc9e60-c465-11cf-8056-444553540000}\0012`]
	if d == nil || UsbKind(ix.classesOf(d), false) != "storage" || usbDeviceName(d) != "Ultra Fit" {
		t.Fatalf("chiavetta: %+v", d)
	}
	phone := ix.byKey[`{eec5ad98-8080-425f-922a-dabf3de3f69a}\0003`]
	if name := usbDeviceName(phone); name == "Galaxy di Mario" || name == "SAMSUNG_Android" {
		t.Errorf("nome di un dispositivo portatile non mascherato: %q", name)
	}
}
