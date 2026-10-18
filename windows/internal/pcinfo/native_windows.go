//go:build windows

package pcinfo

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"lanterna/internal/scan"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx  = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64        = kernel32.NewProc("GetTickCount64")
	procGetSystemTimes        = kernel32.NewProc("GetSystemTimes")
	procGetSystemPowerStatus  = kernel32.NewProc("GetSystemPowerStatus")
	procK32GetProcessMemInfo  = kernel32.NewProc("K32GetProcessMemoryInfo")
	powrprof                  = windows.NewLazySystemDLL("powrprof.dll")
	procPowerGetActiveScheme  = powrprof.NewProc("PowerGetActiveScheme")
	procPowerReadFriendlyName = powrprof.NewProc("PowerReadFriendlyName")
)

const createNoWindow = 0x08000000

// Collect legge i dati del computer. Non fallisce se una parte non è
// leggibile: i limiti finiscono in Notes.
func Collect(ctx context.Context) (*scan.PcData, error) {
	pc := &scan.PcData{}
	var ps *psOut
	var psErr error
	var smart map[string]diskSmart
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ps, psErr = runPS(ctx)
	}()
	go func() {
		defer wg.Done()
		smart = readSmart(ctx)
	}()

	pc.OS = osInfo()
	pc.CPU = cpuInfo()
	pc.Memory = memInfo()
	pc.Volumes = volumes()
	pc.Power, pc.Battery = powerInfo()
	pc.Startup = startupItems()
	pc.Updates = &scan.UpdateInfo{}
	pc.Updates.RebootReasons = pendingReboot()
	pc.Updates.PendingReboot = len(pc.Updates.RebootReasons) > 0
	pc.Hardware = hardwareNative()
	vram := gpuVRAM()
	wg.Wait()

	sysDrive := os.Getenv("SystemDrive")
	if sysDrive == "" {
		sysDrive = "C:"
	}
	if psErr != nil {
		pc.Notes = append(pc.Notes, "Dischi fisici, eventi di sistema, antivirus e aggiornamenti non sono stati letti: PowerShell non ha risposto ("+psErr.Error()+").")
	} else {
		merge(pc, ps, sysDrive)
		smartOf(pc, smart)
		for i := range pc.GPUs {
			pc.GPUs[i].VRAMMB = vram[strings.ToLower(pc.GPUs[i].Name)]
		}
		if ps.Errors["events"] != "" {
			pc.Notes = append(pc.Notes, "Il registro eventi di sistema non è leggibile da questo account.")
		}
	}
	if len(pc.Disks) > 0 {
		has := false
		for _, d := range pc.Disks {
			if d.Reliability != nil || len(d.Smart) > 0 || d.NVMe != nil {
				has = true
			}
		}
		if !has && !windows.GetCurrentProcessToken().IsElevated() {
			pc.Notes = append(pc.Notes, "Temperatura, usura e ore di funzionamento dei dischi (dati SMART) si leggono solo avviando Polaris come amministratore.")
		}
	}
	return pc, nil
}

// SampleLoad misura per la durata indicata il carico della CPU e i processi
// che la usano di più. Va eseguito quando le altre misure sono finite, per non
// contare il lavoro dell'analisi stessa.
func SampleLoad(ctx context.Context, d time.Duration) (*float64, []scan.ProcessInfo) {
	i1, k1, u1, ok1 := systemTimes()
	p1 := processes()
	t1 := time.Now()
	select {
	case <-time.After(d):
	case <-ctx.Done():
		return nil, nil
	}
	i2, k2, u2, ok2 := systemTimes()
	p2 := processes()
	elapsed := time.Since(t1)
	var load *float64
	if ok1 && ok2 {
		load = loadOf(i2-i1, (k2-k1)+(u2-u1))
	}
	return load, GroupProcesses(p1, p2, elapsed, runtime.NumCPU(), 8)
}

// CPULoad misura il carico medio della CPU per la durata indicata (nil se non
// misurabile).
func CPULoad(ctx context.Context, d time.Duration) *float64 {
	i1, k1, u1, ok1 := systemTimes()
	select {
	case <-time.After(d):
	case <-ctx.Done():
		return nil
	}
	i2, k2, u2, ok2 := systemTimes()
	if !ok1 || !ok2 {
		return nil
	}
	return loadOf(i2-i1, (k2-k1)+(u2-u1))
}

// OnAC dice se il computer è collegato alla corrente (nil se non si sa).
func OnAC() *bool {
	var s systemPowerStatus
	if r, _, _ := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&s))); r == 0 || s.ACLineStatus > 1 {
		return nil
	}
	ac := s.ACLineStatus == 1
	return &ac
}

func runPS(ctx context.Context) (*psOut, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", PSScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		var ee *exec.Error
		if errors.As(err, &ee) {
			return nil, errors.New("non disponibile")
		}
		return nil, err
	}
	return parsePS(string(out))
}

func ft(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }

func systemTimes() (idle, kernel, user uint64, ok bool) {
	var i, k, u windows.Filetime
	r, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&i)), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u)))
	return ft(i), ft(k), ft(u), r != 0
}

func osInfo() *scan.PcOS {
	v := windows.RtlGetVersion()
	o := &scan.PcOS{Build: int(v.BuildNumber), Server: v.ProductType != 1}
	product := ""
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		product, _, _ = k.GetStringValue("ProductName")
		if o.Version, _, _ = k.GetStringValue("DisplayVersion"); o.Version == "" {
			o.Version, _, _ = k.GetStringValue("ReleaseId")
		}
		o.Edition, _, _ = k.GetStringValue("EditionID")
		if ubr, _, err := k.GetIntegerValue("UBR"); err == nil {
			o.UBR = int(ubr)
		}
		if inst, _, err := k.GetIntegerValue("InstallDate"); err == nil && inst > 0 {
			o.InstallDate = time.Unix(int64(inst), 0).UTC().Format("2006-01-02")
		}
		k.Close()
	}
	o.Name = OSName(product, o.Build, o.Server)
	arch := os.Getenv("PROCESSOR_ARCHITEW6432")
	if arch == "" {
		arch = os.Getenv("PROCESSOR_ARCHITECTURE")
	}
	o.Arch = map[string]string{"AMD64": "x64", "ARM64": "ARM64", "x86": "x86"}[arch]
	if r, _, _ := procGetTickCount64.Call(); r != 0 {
		up := time.Duration(r) * time.Millisecond
		o.UptimeSec = int64(up.Seconds())
		o.BootTime = time.Now().Add(-up).UTC().Format(time.RFC3339)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Power`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue("HiberbootEnabled"); err == nil {
			b := v != 0
			o.FastStartup = &b
		}
		k.Close()
	}
	return o
}

func cpuInfo() *scan.PcCPU {
	c := &scan.PcCPU{Threads: runtime.NumCPU()}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		name, _, _ := k.GetStringValue("ProcessorNameString")
		c.Name = strings.Join(strings.Fields(name), " ")
		if mhz, _, err := k.GetIntegerValue("~MHz"); err == nil {
			c.MaxMHz = int(mhz)
		}
		k.Close()
	}
	return c
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func memInfo() *scan.PcMemory {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m))); r == 0 || m.TotalPhys == 0 {
		return nil
	}
	mb := func(v uint64) int64 { return int64(v >> 20) }
	return &scan.PcMemory{
		TotalMB:       mb(m.TotalPhys),
		AvailableMB:   mb(m.AvailPhys),
		CommitMB:      mb(m.TotalPageFile - m.AvailPageFile),
		CommitLimitMB: mb(m.TotalPageFile),
	}
}

func volumes() []scan.Volume {
	// Le finestre "inserire un disco" per i lettori di schede vuoti non
	// compaiono: il runtime di Go imposta SEM_FAILCRITICALERRORS all'avvio.
	n, err := windows.GetLogicalDriveStrings(0, nil)
	if err != nil || n == 0 {
		return nil
	}
	buf := make([]uint16, n)
	if _, err := windows.GetLogicalDriveStrings(n, &buf[0]); err != nil {
		return nil
	}
	sys := strings.ToUpper(os.Getenv("SystemDrive"))
	out := []scan.Volume{}
	// Il buffer contiene le radici separate da NUL ("C:\", "D:\", ...):
	// UTF16ToString si fermerebbe alla prima, quindi si scorre a mano.
	for i := 0; i < len(buf); {
		j := i
		for j < len(buf) && buf[j] != 0 {
			j++
		}
		if j == i {
			break
		}
		root := windows.UTF16ToString(buf[i:j])
		i = j + 1
		p, _ := windows.UTF16PtrFromString(root)
		kind := ""
		switch windows.GetDriveType(p) {
		case windows.DRIVE_FIXED:
			kind = "fixed"
		case windows.DRIVE_REMOVABLE:
			kind = "removable"
		default:
			continue // rete, CD, RAM: esclusi (un'unità di rete scollegata potrebbe bloccare)
		}
		var free, total, totalFree uint64
		if windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree) != nil || total == 0 {
			continue
		}
		label := make([]uint16, 261)
		fs := make([]uint16, 261)
		_ = windows.GetVolumeInformation(p, &label[0], uint32(len(label)), nil, nil, nil, &fs[0], uint32(len(fs)))
		letter := strings.ToUpper(strings.TrimRight(root, `\`))
		out = append(out, scan.Volume{
			Letter: letter,
			Label:  windows.UTF16ToString(label),
			FS:     windows.UTF16ToString(fs),
			Kind:   kind,
			SizeGB: round1(float64(total) / 1e9),
			FreeGB: round1(float64(totalFree) / 1e9),
			System: letter == sys,
		})
	}
	return out
}

type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

func powerInfo() (*scan.PowerInfo, *scan.Battery) {
	p := &scan.PowerInfo{}
	var b *scan.Battery
	var s systemPowerStatus
	if r, _, _ := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&s))); r != 0 {
		if s.ACLineStatus <= 1 {
			ac := s.ACLineStatus == 1
			p.OnAC = &ac
		}
		p.HasBattery = s.BatteryFlag != 128 && s.BatteryFlag != 255
		p.BatterySaver = s.SystemStatusFlag == 1
		if p.HasBattery && s.BatteryLifePercent <= 100 {
			pct := int(s.BatteryLifePercent)
			b = &scan.Battery{ChargePct: &pct}
		}
	}
	var guid *windows.GUID
	if procPowerGetActiveScheme.Find() == nil {
		if r, _, _ := procPowerGetActiveScheme.Call(0, uintptr(unsafe.Pointer(&guid))); r == 0 && guid != nil {
			p.PlanKind = PlanKind(guid.String())
			var size uint32
			procPowerReadFriendlyName.Call(0, uintptr(unsafe.Pointer(guid)), 0, 0, 0, uintptr(unsafe.Pointer(&size)))
			if size > 0 && size < 4096 {
				name := make([]uint16, size/2+1)
				if r, _, _ := procPowerReadFriendlyName.Call(0, uintptr(unsafe.Pointer(guid)), 0, 0, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
					p.Plan = windows.UTF16ToString(name)
				}
			}
			windows.LocalFree(windows.Handle(unsafe.Pointer(guid)))
		}
	}
	return p, b
}

func approved(root registry.Key, sub string) map[string]bool {
	out := map[string]bool{}
	k, err := registry.OpenKey(root, `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\`+sub, registry.QUERY_VALUE)
	if err != nil {
		return out
	}
	defer k.Close()
	names, _ := k.ReadValueNames(0)
	for _, n := range names {
		if b, _, err := k.GetBinaryValue(n); err == nil {
			out[strings.ToLower(n)] = StartupEnabled(b)
		}
	}
	return out
}

func startupItems() []scan.StartupItem {
	profile := os.Getenv("USERPROFILE")
	out := []scan.StartupItem{}
	keys := []struct {
		root     registry.Key
		path     string
		approved string
		loc      string
	}{
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, "Run", "user"},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "Run", "machine"},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "Run32", "machine32"},
	}
	for _, kd := range keys {
		k, err := registry.OpenKey(kd.root, kd.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		ok := approved(kd.root, kd.approved)
		names, _ := k.ReadValueNames(0)
		for _, n := range names {
			if n == "" {
				continue
			}
			cmd, _, _ := k.GetStringValue(n)
			en, found := ok[strings.ToLower(n)]
			out = append(out, scan.StartupItem{Name: n, Command: SanitizeCommand(cmd, profile), Location: kd.loc, Enabled: !found || en})
		}
		k.Close()
	}
	folders := []struct {
		dir  string
		root registry.Key
		loc  string
	}{
		{filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`), registry.CURRENT_USER, "user-folder"},
		{filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`), registry.LOCAL_MACHINE, "common-folder"},
	}
	for _, f := range folders {
		entries, err := os.ReadDir(f.dir)
		if err != nil {
			continue
		}
		ok := approved(f.root, "StartupFolder")
		for _, e := range entries {
			if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			en, found := ok[strings.ToLower(e.Name())]
			out = append(out, scan.StartupItem{Name: strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())), Command: SanitizeCommand(filepath.Join(f.dir, e.Name()), profile), Location: f.loc, Enabled: !found || en})
		}
	}
	return out
}

func pendingReboot() []string {
	var reasons []string
	keyExists := func(path string) bool {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		k.Close()
		return true
	}
	if keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`) {
		reasons = append(reasons, "componenti di Windows")
	}
	if keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) {
		reasons = append(reasons, "Windows Update")
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringsValue("PendingFileRenameOperations"); err == nil && len(v) > 0 {
			reasons = append(reasons, "file da sostituire al riavvio")
		}
		k.Close()
	}
	return reasons
}

type processMemoryCountersEx struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

func processes() []ProcSample {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	self := uint32(os.Getpid())
	var out []ProcSample
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		pid := pe.ProcessID
		if pid == 0 || pid == 4 || pid == self {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			continue // processi protetti: il loro carico resta nel totale di sistema
		}
		s := ProcSample{PID: pid, Name: windows.UTF16ToString(pe.ExeFile[:])}
		var c, e, k, u windows.Filetime
		if windows.GetProcessTimes(h, &c, &e, &k, &u) == nil {
			s.CPU = ft(k) + ft(u)
		}
		var m processMemoryCountersEx
		m.CB = uint32(unsafe.Sizeof(m))
		if r, _, _ := procK32GetProcessMemInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&m)), uintptr(m.CB)); r != 0 {
			s.Memory = uint64(m.WorkingSetSize)
		}
		windows.CloseHandle(h)
		out = append(out, s)
	}
	return out
}
