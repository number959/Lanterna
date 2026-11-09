//go:build windows

package pcinfo

import (
	"context"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"lanterna/internal/scan"
)

var (
	winspool              = windows.NewLazySystemDLL("winspool.drv")
	procEnumPrintersW     = winspool.NewProc("EnumPrintersW")
	procOpenPrinterW      = winspool.NewProc("OpenPrinterW")
	procClosePrinter      = winspool.NewProc("ClosePrinter")
	procEnumJobsW         = winspool.NewProc("EnumJobsW")
	procGetDefaultPrinter = winspool.NewProc("GetDefaultPrinterW")
)

// printerInfo2 è PRINTER_INFO_2W (winspool.h). Commento e posizione (testo
// libero, a volte nomi di persone o stanze) non vengono esportati.
type printerInfo2 struct {
	ServerName, PrinterName, ShareName, PortName, DriverName, Comment, Location *uint16
	DevMode                                                                     uintptr
	SepFile, PrintProcessor, Datatype, Parameters                               *uint16
	SecurityDescriptor                                                          uintptr
	Attributes, Priority, DefaultPriority, StartTime, UntilTime, Status, Jobs   uint32
	AveragePPM                                                                  uint32
}

// jobInfo1 è JOB_INFO_1W. Titolo del documento, utente e computer non
// vengono mai copiati: servono solo stato e ora di invio.
type jobInfo1 struct {
	JobID                                                uint32
	PrinterName, MachineName, UserName, Document         *uint16
	Datatype, StatusText                                 *uint16
	Status, Priority, Position, TotalPages, PagesPrinted uint32
	Submitted                                            windows.Systemtime
}

const (
	printerEnumLocal       = 0x2
	printerEnumConnections = 0x4
	printerAttrShared      = 0x8
	printerAttrWorkOffline = 0x400
)

// enumPrinters chiama EnumPrintersW con il protocollo a due chiamate.
func enumPrinters(flags, level uint32) ([]byte, uint32, bool) {
	var need, n uint32
	procEnumPrintersW.Call(uintptr(flags), 0, uintptr(level), 0, 0, uintptr(unsafe.Pointer(&need)), uintptr(unsafe.Pointer(&n)))
	if need == 0 {
		// Nessuna stampante, oppure il servizio di stampa non risponde.
		r, _, _ := procEnumPrintersW.Call(uintptr(flags), 0, uintptr(level), 0, 0, uintptr(unsafe.Pointer(&need)), uintptr(unsafe.Pointer(&n)))
		return nil, 0, r != 0
	}
	buf := make([]byte, need)
	r, _, _ := procEnumPrintersW.Call(uintptr(flags), 0, uintptr(level), uintptr(unsafe.Pointer(&buf[0])), uintptr(need), uintptr(unsafe.Pointer(&need)), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return nil, 0, false
	}
	return buf, n, true
}

// printerJobs conta i lavori in coda di una stampante.
func printerJobs(name string, now time.Time) (stuck, failed, oldest int) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	var h uintptr
	if r, _, _ := procOpenPrinterW.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&h)), 0); r == 0 {
		return
	}
	defer procClosePrinter.Call(h)
	var need, n uint32
	procEnumJobsW.Call(h, 0, 100, 1, 0, 0, uintptr(unsafe.Pointer(&need)), uintptr(unsafe.Pointer(&n)))
	if need == 0 {
		return
	}
	buf := make([]byte, need)
	if r, _, _ := procEnumJobsW.Call(h, 0, 100, 1, uintptr(unsafe.Pointer(&buf[0])), uintptr(need), uintptr(unsafe.Pointer(&need)), uintptr(unsafe.Pointer(&n))); r == 0 || n == 0 {
		return
	}
	for _, j := range unsafe.Slice((*jobInfo1)(unsafe.Pointer(&buf[0])), n) {
		st := j.Submitted
		sub := time.Date(int(st.Year), time.Month(st.Month), int(st.Day), int(st.Hour), int(st.Minute), int(st.Second), 0, time.UTC)
		f, s, age := JobState(j.Status, sub, now)
		if f {
			failed++
		}
		if s {
			stuck++
		}
		if age > oldest {
			oldest = age
		}
	}
	return
}

func defaultPrinter() string {
	var n uint32
	procGetDefaultPrinter.Call(0, uintptr(unsafe.Pointer(&n)))
	if n == 0 || n > 4096 {
		return ""
	}
	buf := make([]uint16, n)
	if r, _, _ := procGetDefaultPrinter.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

// readPrinting legge stampanti, code e servizio di stampa.
func readPrinting(ctx context.Context) *scan.PrintingInfo {
	p := &scan.PrintingInfo{}
	if m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT); err == nil {
		p.Spooler = serviceState(m, "Spooler")
		windows.CloseServiceHandle(m)
	}
	buf, n, ok := enumPrinters(printerEnumLocal, 2)
	if !ok {
		return p
	}
	def := strings.ToLower(defaultPrinter())
	now := time.Now().UTC()
	p.Printers = []scan.Printer{}
	if n > 0 {
		for _, pi := range unsafe.Slice((*printerInfo2)(unsafe.Pointer(&buf[0])), n) {
			if ctx.Err() != nil {
				break
			}
			name := windows.UTF16PtrToString(pi.PrinterName)
			port := windows.UTF16PtrToString(pi.PortName)
			driver := windows.UTF16PtrToString(pi.DriverName)
			pr := scan.Printer{
				Name: name, Kind: PrinterKind(port, driver), Default: strings.ToLower(name) == def,
				Shared: pi.Attributes&printerAttrShared != 0, Port: port, Driver: driver,
				Status: pi.Status, Flags: PrinterFlags(pi.Status), WorkOffline: pi.Attributes&printerAttrWorkOffline != 0, Jobs: int(pi.Jobs),
			}
			if pi.Jobs > 0 {
				pr.Stuck, pr.JobErrors, pr.OldestMin = printerJobs(name, now)
			}
			p.Printers = append(p.Printers, pr)
		}
	}
	if _, c, ok := enumPrinters(printerEnumConnections, 4); ok {
		p.Connections = int(c)
	}
	return p
}
