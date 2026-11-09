package pcinfo

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"lanterna/internal/scan"
)

func TestSanitizeHardwareID(t *testing.T) {
	cases := map[string]string{
		`PCI\VEN_10DE&DEV_2206&SUBSYS_38811462&REV_A1`:                         `PCI\VEN_10DE&DEV_2206&SUBSYS_38811462&REV_A1`,
		`PCI\VEN_8086&DEV_A0E8&CC_0C0300`:                                      `PCI\VEN_8086&DEV_A0E8&CC_0C0300`,
		`USB\VID_046D&PID_C52B&REV_1201&MI_00`:                                 `USB\VID_046D&PID_C52B&REV_1201&MI_00`,
		`HID\VID_046D&PID_C52B&REV_1201&MI_00&Col01`:                           `HID\VID_046D&PID_C52B&REV_1201&MI_00&COL01`,
		`ACPI\VEN_INT&DEV_33A0`:                                                `ACPI\VEN_INT&DEV_33A0`,
		`ACPI\PNP0A08`:                                                         `ACPI\PNP0A08`,
		`ACPI\ACPI0003`:                                                        `ACPI\ACPI0003`,
		`HDAUDIO\FUNC_01&VEN_10EC&DEV_0236&SUBSYS_1043194E&REV_1000`:           `HDAUDIO\VEN_10EC&DEV_0236&SUBSYS_1043194E&REV_1000`,
		`DISPLAY\DELA0B2`:                                                      `DISPLAY\DELA0B2`,
		`USBSTOR\DiskSanDisk_Cruzer_Blade____1.00`:                             `USBSTOR`,
		`SCSI\DiskNVMe____Samsung_SSD_970_2B2QEXE7`:                            `SCSI`,
		`SWD\MMDEVAPI\{0.0.0.00000000}.{a1b2c3d4-0000-0000-0000-000000000000}`: `SWD`,
		// L'ID di un dispositivo Bluetooth LE contiene l'indirizzo: va scartato.
		`BTHLE\Dev_a4c1381f2e3d`: `BTHLE`,
		`BTHENUM\{0000110b-0000-1000-8000-00805f9b34fb}_VID&0002004c_PID&7314`: `BTHENUM`,
		`{5d624f94-8850-40c3-a3fa-a4fd2080baf3}\vwifimp_wfd`:                   ``,
		`senza-barra`: ``,
		``:            ``,
	}
	for in, want := range cases {
		if got := SanitizeHardwareID(in); got != want {
			t.Errorf("SanitizeHardwareID(%q) = %q, attesa %q", in, got, want)
		}
	}
}

func TestDeviceName(t *testing.T) {
	cases := []struct{ name, class, enum, want string }{
		{"NVIDIA GeForce RTX 3070", "Display", "PCI", "NVIDIA GeForce RTX 3070"},
		{"Controller host compatibile con xHCI USB", "USB", "PCI", "Controller host compatibile con xHCI USB"},
		{"Intel(R) Wireless Bluetooth(R)", "Bluetooth", "USB", "Intel(R) Wireless Bluetooth(R)"},
		{"iPhone di Anna", "WPD", "USB", "Dispositivo portatile"},
		{"AirPods di Anna", "Bluetooth", "BTHENUM", "Dispositivo Bluetooth"},
		{"Cuffie (AirPods di Anna)", "MEDIA", "BTHHFENUM", "Dispositivo audio"},
		{`\\prn-corp3\stug-2633-clr`, "PrintQueue", "SWD", "Coda di stampa"},
		{"HP LaserJet su server-ufficio", "Printer", "WSDPRINT", "Stampante"},
		{`Stampante \\server\ufficio`, "", "ROOT", "Dispositivo"},
		{"TV del salotto", "", "SWD", "Dispositivo"},
		{"", "Net", "PCI", "Scheda di rete"},
		{"  Scheda   di rete  Intel ", "Net", "PCI", "Scheda di rete Intel"},
	}
	for _, c := range cases {
		if got := DeviceName(c.name, c.class, c.enum); got != c.want {
			t.Errorf("DeviceName(%q, %q, %q) = %q, atteso %q", c.name, c.class, c.enum, got, c.want)
		}
	}
	if got := DeviceName(strings.Repeat("x", 300), "Display", "PCI"); len([]rune(got)) != 120 {
		t.Errorf("nome non accorciato: %d caratteri", len([]rune(got)))
	}
}

func TestInboxAndDriverFile(t *testing.T) {
	for inf, inbox := range map[string]bool{"oem42.inf": false, "OEM7.INF": false, "machine.inf": true, "netrtwlane.inf": true, "oem.inf": true, "": false} {
		if IsInboxInf(inf) != inbox {
			t.Errorf("IsInboxInf(%q) = %v", inf, !inbox)
		}
	}
	cases := []struct {
		path, svc string
		kernel    bool
		want      string
	}{
		{`\SystemRoot\System32\drivers\nvlddmkm.sys`, "nvlddmkm", true, "nvlddmkm.sys"},
		{`System32\DriverStore\FileRepository\nv_dispi.inf_amd64_x\nvlddmkm.SYS`, "nvlddmkm", true, "nvlddmkm.sys"},
		{`\??\C:\Program Files\Vendor\filtro.sys`, "filtro", true, "filtro.sys"},
		{`"C:\Program Files\Vendor\servizio.exe" -k`, "servizio", false, "servizio.exe"},
		{`C:\Windows\system32\svchost.exe -k LocalService -p`, "x", false, "svchost.exe"},
		{`C:\Windows\system32\svchost.exe`, "x", false, "svchost.exe"},
		{"", "storahci", true, "storahci.sys"},
		{"", "AudioSrv", false, ""},
	}
	for _, c := range cases {
		if got := DriverFile(c.path, c.svc, c.kernel); got != c.want {
			t.Errorf("DriverFile(%q) = %q, atteso %q", c.path, got, c.want)
		}
	}
	if NTStatusHex(0) != "" || NTStatusHex(0xC0000034) != "0xC0000034" {
		t.Error("NTStatusHex")
	}
}

func utf16le(ss ...string) []byte {
	var b []byte
	for _, s := range ss {
		for _, u := range utf16.Encode([]rune(s)) {
			b = binary.LittleEndian.AppendUint16(b, u)
		}
		b = binary.LittleEndian.AppendUint16(b, 0)
	}
	return binary.LittleEndian.AppendUint16(b, 0)
}

func TestPropDecoding(t *testing.T) {
	if got := propString(utf16le("Scheda è video")); got != "Scheda è video" {
		t.Errorf("propString = %q", got)
	}
	got := propStringList(utf16le(`PCI\VEN_1&DEV_2`, `PCI\VEN_1`))
	if len(got) != 2 || got[1] != `PCI\VEN_1` {
		t.Errorf("propStringList = %q", got)
	}
	if v, ok := propUint32([]byte{0x34, 0, 0, 0xc0}); !ok || v != 0xC0000034 {
		t.Errorf("propUint32 = %x", v)
	}
	ft := func(tm time.Time) []byte {
		return binary.LittleEndian.AppendUint64(nil, uint64(tm.UnixNano()/100+116444736000000000))
	}
	// Mezzanotte UTC, mezzanotte italiana (22:00 del giorno prima in UTC) e di New York.
	for _, tm := range []time.Time{
		time.Date(2006, 6, 21, 0, 0, 0, 0, time.UTC),
		time.Date(2006, 6, 20, 22, 0, 0, 0, time.UTC),
		time.Date(2006, 6, 21, 5, 0, 0, 0, time.UTC),
	} {
		if got := filetimeDate(ft(tm)); got != "2006-06-21" {
			t.Errorf("filetimeDate(%v) = %q", tm, got)
		}
	}
	if filetimeDate([]byte{0, 0, 0, 0, 0, 0, 0, 0}) != "" || filetimeDate(nil) != "" {
		t.Error("data vuota non riconosciuta")
	}
}

func TestBuildDevices(t *testing.T) {
	raw := []rawDevice{
		{Name: "NVIDIA GeForce RTX 3070", Class: "Display", Enumerator: "PCI", HardwareIDs: []string{`PCI\VEN_10DE&DEV_2484&SUBSYS_38811462&REV_A1`, `PCI\VEN_10DE&DEV_2484`},
			Service: "nvlddmkm", Provider: "NVIDIA", Version: "31.0.15.3623", Date: "2024-03-12", Inf: "oem42.inf", File: "nvlddmkm.sys"},
		{Name: "Dispositivo sconosciuto", Enumerator: "ACPI", HardwareIDs: []string{`ACPI\VEN_INT&DEV_33A0`}, Problem: 28, Status: 0xC0000490},
		{Name: "AirPods di Anna", Class: "Bluetooth", Enumerator: "BTHENUM", Problem: 22, Inf: "bth.inf", Provider: "Microsoft"},
		{Name: "Controller standard SATA AHCI", Class: "HDC", Enumerator: "PCI", Service: "storahci", Inf: "mshdc.inf", Provider: "Microsoft", Date: "2006-06-21", File: "storahci.sys"},
		{Name: "Hub USB generico", Class: "USB", Enumerator: "USB", Service: "USBHUB3", Inf: "usbhub3.inf", Provider: "Microsoft", File: "usbhub3.sys"},
		{Name: "Realtek Audio", Class: "MEDIA", Enumerator: "HDAUDIO", Problem: 10, Status: 0xC000009A, Inf: "oem9.inf", Provider: "Realtek", Date: "2017-05-02"},
	}
	d := BuildDevices(raw, map[string]bool{"storahci.sys": true})
	if d.Total != 6 || d.Problems != 3 {
		t.Fatalf("totale %d, problemi %d", d.Total, d.Problems)
	}
	var names []string
	for _, it := range d.Items {
		names = append(names, it.Name)
	}
	// Prima i problemi (il disattivato dopo), poi i driver di terze parti e il driver delle schermate blu.
	want := "Dispositivo sconosciuto|Realtek Audio|Dispositivo Bluetooth|NVIDIA GeForce RTX 3070|Controller standard SATA AHCI"
	if strings.Join(names, "|") != want {
		t.Fatalf("dispositivi: %s", strings.Join(names, "|"))
	}
	unk := d.Items[0]
	if unk.Problem != 28 || unk.ProblemStatus != "0xC0000490" || unk.HardwareID != `ACPI\VEN_INT&DEV_33A0` || unk.Driver != nil {
		t.Errorf("dispositivo sconosciuto: %+v", unk)
	}
	gpu := d.Items[3]
	if gpu.Driver == nil || gpu.Driver.Inbox || gpu.Driver.Inf != "oem42.inf" || gpu.Driver.File != "nvlddmkm.sys" || gpu.HardwareID != `PCI\VEN_10DE&DEV_2484&SUBSYS_38811462&REV_A1` {
		t.Errorf("scheda video: %+v %+v", gpu, gpu.Driver)
	}
	hdc := d.Items[4]
	if hdc.Driver == nil || !hdc.Driver.Inbox || hdc.Problem != 0 {
		t.Errorf("controller indicato dalle schermate blu: %+v", hdc)
	}
	if d.Items[2].ProblemStatus != "" || d.Items[2].Problem != 22 {
		t.Errorf("disattivato: %+v", d.Items[2])
	}
	if len(d.Classes) != 6 || d.Classes[0].Problems != 1 {
		t.Errorf("classi: %+v", d.Classes)
	}
	for _, c := range d.Classes {
		if c.Class == "" && c.Count != 1 {
			t.Errorf("classe vuota: %+v", c)
		}
	}
}

func TestCrashSuspectsAndCodeIntegrity(t *testing.T) {
	c := &scan.CrashData{Dumps: []scan.CrashDump{
		{Probable: &scan.CrashCulprit{Driver: "NVLDDMKM.SYS"}},
		{},
		{Probable: &scan.CrashCulprit{Driver: `\SystemRoot\system32\drivers\storahci.sys`}},
	}, MemoryDump: &scan.CrashDump{Probable: &scan.CrashCulprit{Driver: "ntfs.sys"}}}
	s := CrashSuspects(c)
	if len(s) != 3 || !s["nvlddmkm.sys"] || !s["storahci.sys"] || !s["ntfs.sys"] {
		t.Errorf("sospetti: %v", s)
	}
	if len(CrashSuspects(nil)) != 0 {
		t.Error("nil")
	}
	ci := CodeIntegrityOf(0x401)
	if !ci.Enabled || ci.TestSigning || ci.DebugMode || !ci.HVCI || ci.Options != 0x401 {
		t.Errorf("0x401: %+v", ci)
	}
	ci = CodeIntegrityOf(0x83)
	if !ci.Enabled || !ci.TestSigning || !ci.DebugMode || ci.HVCI {
		t.Errorf("0x83: %+v", ci)
	}
}
