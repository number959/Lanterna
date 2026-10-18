//go:build windows

package pcinfo

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"lanterna/internal/scan"
)

// Codici di controllo e costanti delle intestazioni di Windows (winioctl.h,
// ntddscsi.h, ntddstor.h).
const (
	ioctlStorageQueryProperty = 0x002D1400 // IOCTL_STORAGE_QUERY_PROPERTY
	ioctlAtaPassThrough       = 0x0004D02C // IOCTL_ATA_PASS_THROUGH
	smartRcvDriveData         = 0x0007C088 // SMART_RCV_DRIVE_DATA

	storageDeviceProperty                  = 0
	storageAdapterProtocolSpecificProperty = 49
	storageDeviceProtocolSpecificProperty  = 50

	protocolTypeNvme    = 3
	nvmeDataTypeLogPage = 2
	nvmeLogPageHealth   = 2

	ataFlagsDrdyRequired = 0x01
	ataFlagsDataIn       = 0x02

	smartReadData       = 0xD0 // registro Features del comando SMART
	smartReadThresholds = 0xD1
)

// Tipi di bus di STORAGE_BUS_TYPE.
const (
	busUnknown = 0
	busSCSI    = 1
	busATA     = 3
	busRAID    = 8
	busSAS     = 10
	busSATA    = 11
	busNVMe    = 17
)

// smartBudget limita la lettura: un disco meccanico fermo impiega qualche
// secondo a ripartire, uno guasto può non rispondere affatto.
const smartBudget = 15 * time.Second

// readSmart legge i dati SMART dei dischi fisici. Per i dischi ATA serve un
// account amministratore (il comando richiede l'accesso in lettura e
// scrittura al dispositivo, anche se non scrive nulla); per i dischi NVMe si
// tenta anche senza. Se il tempo massimo scade o l'analisi viene annullata si
// restituisce ciò che è stato letto fino a quel momento.
func readSmart(ctx context.Context) map[string]diskSmart {
	type item struct {
		id string
		s  diskSmart
	}
	ch := make(chan item, 32)
	go func() {
		defer close(ch)
		for n := range 32 {
			if s, ok := smartDisk(n); ok {
				ch <- item{strconv.Itoa(n), s}
			}
		}
	}()
	out := map[string]diskSmart{}
	deadline := time.After(smartBudget)
	for {
		select {
		case it, ok := <-ch:
			if !ok {
				return out
			}
			out[it.id] = it.s
		case <-deadline:
			return out
		case <-ctx.Done():
			return out
		}
	}
}

// smartDisk legge il disco numero n; ok è falso se il disco non esiste o non
// ha restituito dati.
func smartDisk(n int) (diskSmart, bool) {
	h, err := openDisk(n, 0)
	if err != nil {
		return diskSmart{}, false
	}
	bus, ok := busType(h)
	windows.CloseHandle(h)
	if !ok {
		return diskSmart{}, false
	}
	switch bus {
	case busNVMe:
		for _, access := range []uint32{windows.GENERIC_READ | windows.GENERIC_WRITE, 0} {
			h, err := openDisk(n, access)
			if err != nil {
				continue
			}
			nv := nvmeHealth(h)
			windows.CloseHandle(h)
			if nv != nil {
				return diskSmart{NVMe: nv}, true
			}
		}
	case busATA, busSATA, busRAID, busSCSI, busSAS, busUnknown:
		h, err := openDisk(n, windows.GENERIC_READ|windows.GENERIC_WRITE)
		if err != nil {
			return diskSmart{}, false
		}
		attrs := ataSmart(h)
		windows.CloseHandle(h)
		if len(attrs) > 0 {
			return diskSmart{Attrs: attrs}, true
		}
	}
	return diskSmart{}, false
}

func openDisk(n int, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\PhysicalDrive%d`, n))
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
}

// busType legge il tipo di bus da STORAGE_DEVICE_DESCRIPTOR (campo BusType
// all'offset 28). Non richiede privilegi.
func busType(h windows.Handle) (int, bool) {
	var q [12]byte // STORAGE_PROPERTY_QUERY: StorageDeviceProperty, PropertyStandardQuery
	binary.LittleEndian.PutUint32(q[0:], storageDeviceProperty)
	out := make([]byte, 1024)
	var n uint32
	if err := windows.DeviceIoControl(h, ioctlStorageQueryProperty, &q[0], uint32(len(q)), &out[0], uint32(len(out)), &n, nil); err != nil || n < 32 {
		return 0, false
	}
	return int(binary.LittleEndian.Uint32(out[28:])), true
}

// ataSmart legge attributi e soglie con il passaggio diretto di comandi ATA
// (il metodo dei controller AHCI moderni) e, se non riesce, con l'IOCTL SMART
// classico del driver del disco.
func ataSmart(h windows.Handle) []scan.SmartAttr {
	for _, read := range []func(windows.Handle, byte) ([]byte, error){ataPassThrough, smartRcv} {
		data, err := read(h, smartReadData)
		if err != nil || !smartValid(data) {
			continue
		}
		thr, err := read(h, smartReadThresholds)
		if err != nil || !smartValid(thr) {
			thr = nil // soglie illeggibili: gli attributi restano validi
		}
		return ParseSmart(data, thr)
	}
	return nil
}

// ataPassThroughEx ricalca ATA_PASS_THROUGH_EX: 48 byte a 64 bit, 40 a 32
// (DataBufferOffset è un ULONG_PTR, allineato come uintptr).
type ataPassThroughEx struct {
	Length             uint16
	AtaFlags           uint16
	PathID             uint8
	TargetID           uint8
	Lun                uint8
	ReservedAsUchar    uint8
	DataTransferLength uint32
	TimeOutValue       uint32
	ReservedAsUlong    uint32
	DataBufferOffset   uintptr
	PreviousTaskFile   [8]uint8
	CurrentTaskFile    [8]uint8
}

// ataTaskFile prepara i registri del comando SMART (B0h): Features, Sector
// Count, Sector Number, LBA Mid 4Fh, LBA High C2h, Device, Command.
func ataTaskFile(feature byte) [8]byte {
	return [8]byte{feature, 1, 1, 0x4F, 0xC2, 0xA0, 0xB0, 0}
}

func ataPassThrough(h windows.Handle, feature byte) ([]byte, error) {
	var buf struct {
		apt    ataPassThroughEx
		filler uint32
		data   [512]byte
	}
	buf.apt.Length = uint16(unsafe.Sizeof(buf.apt))
	buf.apt.AtaFlags = ataFlagsDrdyRequired | ataFlagsDataIn
	buf.apt.DataTransferLength = uint32(len(buf.data))
	buf.apt.TimeOutValue = 10 // secondi
	buf.apt.DataBufferOffset = unsafe.Offsetof(buf.data)
	buf.apt.CurrentTaskFile = ataTaskFile(feature)
	size := uint32(unsafe.Sizeof(buf))
	var n uint32
	p := (*byte)(unsafe.Pointer(&buf))
	if err := windows.DeviceIoControl(h, ioctlAtaPassThrough, p, size, p, size, &n, nil); err != nil {
		return nil, err
	}
	// Al ritorno CurrentTaskFile contiene i registri del disco: il bit 0 dello
	// stato (ERR) segnala un comando rifiutato, per esempio SMART disattivato.
	if buf.apt.CurrentTaskFile[6]&0x01 != 0 {
		return nil, errors.New("comando rifiutato dal disco")
	}
	return buf.data[:], nil
}

// smartRcv usa SMART_RCV_DRIVE_DATA. SENDCMDINPARAMS (impaccata) è lunga 33
// byte, l'ultimo è l'inizio del buffer e non si invia; in uscita
// SENDCMDOUTPARAMS ha 16 byte di intestazione prima dei dati.
func smartRcv(h windows.Handle, feature byte) ([]byte, error) {
	in := make([]byte, 32)
	binary.LittleEndian.PutUint32(in[0:], 512) // cBufferSize
	tf := ataTaskFile(feature)
	copy(in[4:12], tf[:]) // IDEREGS; bDriveNumber (offset 12) resta 0
	out := make([]byte, 16+512)
	var n uint32
	if err := windows.DeviceIoControl(h, smartRcvDriveData, &in[0], uint32(len(in)), &out[0], uint32(len(out)), &n, nil); err != nil {
		return nil, err
	}
	if out[4] != 0 { // DRIVERSTATUS.bDriverError
		return nil, fmt.Errorf("errore del driver %d", out[4])
	}
	return out[16:], nil
}

// nvmeHealth chiede al driver NVMe di Windows la pagina di registro 02h. Il
// buffer contiene STORAGE_PROPERTY_QUERY (8 byte senza i parametri),
// STORAGE_PROTOCOL_SPECIFIC_DATA (40 byte) e lo spazio per i dati; in uscita
// lo stesso spazio diventa STORAGE_PROTOCOL_DATA_DESCRIPTOR (Version e Size
// valgono 48) seguito dai dati, che iniziano dove indica ProtocolDataOffset
// (relativo alla struttura del protocollo, all'offset 8).
func nvmeHealth(h windows.Handle) *scan.NVMeHealth {
	for _, prop := range []uint32{storageDeviceProtocolSpecificProperty, storageAdapterProtocolSpecificProperty} {
		buf := make([]byte, 8+40+512)
		binary.LittleEndian.PutUint32(buf[0:], prop)
		binary.LittleEndian.PutUint32(buf[8:], protocolTypeNvme)
		binary.LittleEndian.PutUint32(buf[12:], nvmeDataTypeLogPage)
		binary.LittleEndian.PutUint32(buf[16:], nvmeLogPageHealth)
		binary.LittleEndian.PutUint32(buf[24:], 40)  // ProtocolDataOffset
		binary.LittleEndian.PutUint32(buf[28:], 512) // ProtocolDataLength
		var n uint32
		if err := windows.DeviceIoControl(h, ioctlStorageQueryProperty, &buf[0], uint32(len(buf)), &buf[0], uint32(len(buf)), &n, nil); err != nil {
			continue
		}
		if binary.LittleEndian.Uint32(buf[0:]) != 48 || binary.LittleEndian.Uint32(buf[4:]) != 48 {
			continue
		}
		off, length := int(binary.LittleEndian.Uint32(buf[24:])), int(binary.LittleEndian.Uint32(buf[28:]))
		if off < 40 || length < 512 || 8+off+512 > len(buf) {
			continue
		}
		log := buf[8+off : 8+off+512]
		if nvmeValid(log) {
			return ParseNVMeHealth(log)
		}
	}
	return nil
}
