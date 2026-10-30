//go:build windows

package sensors

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"lanterna/internal/pcinfo"
	"lanterna/internal/pdh"
)

var procGlobalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

// memoryStatusEx è MEMORYSTATUSEX (sysinfoapi.h).
type memoryStatusEx struct {
	length, memoryLoad                          uint32
	totalPhys, availPhys                        uint64
	totalPageFile, availPageFile                uint64
	totalVirtual, availVirtual, availExtVirtual uint64
}

// New prepara il monitor dei sensori di questo PC.
func New() *Monitor { return &Monitor{Open: Open} }

type winSource struct {
	q        *pdh.Query
	counters map[string]pdh.Counter
	cpuName  string
	baseMHz  float64
	elevated bool
	gpus     *gpuReader
	gpuErr   error
	disks    *diskWatcher
}

// Open apre i contatori, le schede video e la lettura delle temperature dei
// dischi. I contatori che questo Windows non ha (per esempio Energy Meter)
// si saltano.
func Open() (Source, error) {
	q, err := pdh.Open()
	if errors.Is(err, pdh.ErrUnavailable) {
		return nil, ErrUnavailable
	}
	if err != nil {
		return nil, err
	}
	s := &winSource{q: q, counters: map[string]pdh.Counter{}}
	var firstErr error
	for key, path := range Counters {
		c, err := q.Add(path)
		if err != nil {
			if firstErr == nil && !pdh.Missing(err) {
				firstErr = err
			}
			continue
		}
		s.counters[key] = c
	}
	if len(s.counters) == 0 {
		q.Close()
		if firstErr != nil {
			return nil, fmt.Errorf("%w (%v)", ErrUnavailable, firstErr)
		}
		return nil, ErrUnavailable
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		s.cpuName, _, _ = k.GetStringValue("ProcessorNameString")
		if v, _, err := k.GetIntegerValue("~MHz"); err == nil {
			s.baseMHz = float64(v)
		}
		k.Close()
	}
	s.elevated = windows.GetCurrentProcessToken().IsElevated()
	s.gpus, s.gpuErr = openGPUs()
	s.disks = watchDisks(30 * time.Second)
	return s, nil
}

func (s *winSource) Collect() error { return s.q.Collect() }

func (s *winSource) Read() (Raw, error) {
	r := Raw{Counters: map[string]map[string]float64{}, CPUName: s.cpuName, BaseMHz: s.baseMHz, Elevated: s.elevated, GPUErr: s.gpuErr}
	for key, c := range s.counters {
		if vals, err := s.q.Values(c); err == nil {
			r.Counters[key] = vals
		}
	}
	var ms memoryStatusEx
	ms.length = uint32(unsafe.Sizeof(ms))
	if r1, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r1 != 0 {
		// Il "file di paging" di MEMORYSTATUSEX è la memoria impegnabile:
		// il totale è il limite, il disponibile ciò che resta.
		r.Memory = &Memory{Total: ms.totalPhys, Avail: ms.availPhys, CommitTotal: ms.totalPageFile - min(ms.availPageFile, ms.totalPageFile), CommitLimit: ms.totalPageFile}
	}
	if s.gpus != nil {
		r.GPUs = s.gpus.read()
	}
	r.Batteries = readBatteries()
	r.Disks = s.disks.snapshot()
	return r, nil
}

func (s *winSource) Close() {
	s.q.Close()
	if s.gpus != nil {
		s.gpus.close()
	}
	s.disks.stop()
}

// ---------------------------------------------------------------- dischi

// Costanti di winioctl.h (vedi anche pcinfo/smart_windows.go).
const (
	ioctlStorageQueryProperty   = 0x002D1400
	storageDeviceProperty       = 0
	storageDeviceSeekPenalty    = 7
	busNVMe                     = 17
	maxDisks                    = 32
	storageDescriptorBusTypeOff = 28
)

// diskWatcher legge modello e tipo dei dischi all'apertura e la temperatura
// ogni intervallo, in un goroutine: la lettura SMART di un disco meccanico
// fermo può richiedere secondi e non deve rallentare le altre misure.
type diskWatcher struct {
	mu    sync.Mutex
	disks map[string]Disk
	done  chan struct{}
	once  sync.Once
}

func watchDisks(every time.Duration) *diskWatcher {
	w := &diskWatcher{disks: map[string]Disk{}, done: make(chan struct{})}
	for n := range maxDisks {
		if d, ok := diskInfo(n); ok {
			d.TempC = nan
			w.disks[fmt.Sprint(n)] = d
		}
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			w.refresh()
			select {
			case <-w.done:
				return
			case <-t.C:
			}
		}
	}()
	return w
}

func (w *diskWatcher) refresh() {
	w.mu.Lock()
	ids := make([]string, 0, len(w.disks))
	for id := range w.disks {
		ids = append(ids, id)
	}
	w.mu.Unlock()
	for _, id := range ids {
		select {
		case <-w.done:
			return
		default:
		}
		var n int
		fmt.Sscan(id, &n)
		// Prima la temperatura che Windows dà senza diritti (con le soglie
		// del disco), poi i dati SMART.
		t, warn, crit, ok := storageTemp(n)
		if !ok {
			warn, crit = nan, nan
			t, ok = pcinfo.DiskTemperature(n)
		}
		w.mu.Lock()
		d := w.disks[id]
		d.WarnC, d.CritC = warn, crit
		if ok {
			d.TempC = t
		} else {
			d.TempC = nan
		}
		w.disks[id] = d
		w.mu.Unlock()
	}
}

func (w *diskWatcher) snapshot() map[string]Disk {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make(map[string]Disk, len(w.disks))
	for k, v := range w.disks {
		out[k] = v
	}
	return out
}

func (w *diskWatcher) stop() { w.once.Do(func() { close(w.done) }) }

// diskInfo legge modello e tipo del disco fisico n con un handle senza
// diritti di accesso: non servono permessi di amministratore. Il numero di
// serie non si legge.
func diskInfo(n int) (Disk, bool) {
	p, err := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\PhysicalDrive%d`, n))
	if err != nil {
		return Disk{}, false
	}
	h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return Disk{}, false
	}
	defer windows.CloseHandle(h)
	out := make([]byte, 1024)
	if !queryProperty(h, storageDeviceProperty, out) {
		return Disk{}, true
	}
	var d Disk
	d.Model = descriptorModel(out)
	if binary.LittleEndian.Uint32(out[storageDescriptorBusTypeOff:]) == busNVMe {
		flash := true
		d.Flash = &flash
	} else {
		sp := make([]byte, 12)
		if queryProperty(h, storageDeviceSeekPenalty, sp) {
			flash := sp[8] == 0 // IncursSeekPenalty
			d.Flash = &flash
		}
	}
	return d, true
}

// storageTemp legge StorageDeviceTemperatureProperty con un handle senza
// diritti di accesso: funziona con gli NVMe del driver di Windows; gli altri
// dischi di solito non rispondono e si passa ai dati SMART.
func storageTemp(n int) (temp, warn, crit float64, valid bool) {
	p, err := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\PhysicalDrive%d`, n))
	if err != nil {
		return nan, nan, nan, false
	}
	h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nan, nan, nan, false
	}
	defer windows.CloseHandle(h)
	out := make([]byte, 24+16*16)
	var q [12]byte
	binary.LittleEndian.PutUint32(q[0:], storageDeviceTemperatureProperty)
	var got uint32
	if windows.DeviceIoControl(h, ioctlStorageQueryProperty, &q[0], uint32(len(q)), &out[0], uint32(len(out)), &got, nil) != nil {
		return nan, nan, nan, false
	}
	return parseStorageTemp(out[:min(int(got), len(out))])
}

func queryProperty(h windows.Handle, id uint32, out []byte) bool {
	var q [12]byte // STORAGE_PROPERTY_QUERY: PropertyId, PropertyStandardQuery
	binary.LittleEndian.PutUint32(q[0:], id)
	var n uint32
	err := windows.DeviceIoControl(h, ioctlStorageQueryProperty, &q[0], uint32(len(q)), &out[0], uint32(len(out)), &n, nil)
	return err == nil && n >= 12
}

// descriptorModel ricava produttore e modello da STORAGE_DEVICE_DESCRIPTOR
// (scostamenti delle stringhe a +12 e +16).
func descriptorModel(b []byte) string {
	str := func(off uint32) string {
		if off == 0 || int(off) >= len(b) {
			return ""
		}
		end := int(off)
		for end < len(b) && b[end] != 0 {
			end++
		}
		return strings.TrimSpace(string(b[off:end]))
	}
	if len(b) < 20 {
		return ""
	}
	vendor := str(binary.LittleEndian.Uint32(b[12:]))
	product := str(binary.LittleEndian.Uint32(b[16:]))
	switch strings.ToUpper(vendor) {
	case "", "ATA", "NVME", "SCSI", "(STANDARD DISK DRIVES)":
		return product
	}
	if strings.HasPrefix(strings.ToUpper(product), strings.ToUpper(vendor)) {
		return product
	}
	return strings.TrimSpace(vendor + " " + product)
}
