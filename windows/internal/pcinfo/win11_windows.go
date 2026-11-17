//go:build windows

package pcinfo

import (
	"context"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"lanterna/internal/scan"
)

var (
	procGetPhysicallyInstalledSystemMemory = kernel32.NewProc("GetPhysicallyInstalledSystemMemory")
	tbsDLL                                 = windows.NewLazySystemDLL("tbs.dll")
	procTbsiGetDeviceInfo                  = tbsDLL.NewProc("Tbsi_GetDeviceInfo")
)

// hwExtraTimeout limita le letture native della 0.14.0: di solito bastano
// pochi millisecondi. Il TPM passa dal servizio TBS e ha un limite suo, così
// un servizio bloccato non fa perdere il resto.
const (
	hwExtraTimeout = 10 * time.Second
	tpmTimeout     = 5 * time.Second
)

// startHardwareExtra avvia in parallelo le letture native per la scheda
// tecnica e i requisiti di Windows 11; la funzione restituita aspetta
// l'esito (false se non è arrivato in tempo).
func startHardwareExtra(ctx context.Context) func() (hwExtra, bool) {
	type result struct {
		x  hwExtra
		ok bool
	}
	ch := make(chan result, 1)
	go func() {
		x, ok := within(ctx, hwExtraTimeout, readHardwareExtra)
		ch <- result{x, ok}
	}()
	return func() (hwExtra, bool) {
		r := <-ch
		return r.x, r.ok
	}
}

// finishHardwareExtra aspetta le letture e completa i dati del computer.
func finishHardwareExtra(pc *scan.PcData, wait func() (hwExtra, bool), ps *psOut, devRaw []rawDevice, devOK bool) {
	x, ok := wait()
	applyHardwareExtra(pc, x, ok, ps, devRaw, devOK, windows.GetCurrentProcessToken().IsElevated())
}

func readHardwareExtra(ctx context.Context) hwExtra {
	x := hwExtra{InstalledMB: installedMB(), Appraiser: readAppraiser(), Wddm: readWddm()}
	x.Displays, _ = readDisplays()
	x.TPM, _ = within(ctx, tpmTimeout, func(context.Context) *string { return tpmVersion() })
	return x
}

// installedMB è la RAM installata secondo le tabelle SMBIOS del firmware
// (GetPhysicallyInstalledSystemMemory, in KB); 0 se non leggibile.
func installedMB() int64 {
	if procGetPhysicallyInstalledSystemMemory.Find() != nil {
		return 0
	}
	var kb uint64
	if r, _, _ := procGetPhysicallyInstalledSystemMemory.Call(uintptr(unsafe.Pointer(&kb))); r == 0 {
		return 0
	}
	return int64(kb / 1024)
}

// tpmDeviceInfo è TPM_DEVICE_INFO (tbs.h): quattro UINT32, 16 byte.
type tpmDeviceInfo struct {
	structVersion    uint32
	tpmVersion       uint32
	tpmInterfaceType uint32
	tpmImpRevision   uint32
}

// tpmVersion chiede al servizio TBS la versione del TPM con
// Tbsi_GetDeviceInfo (Windows 8 e successivi, documentata senza privilegi).
// structVersion vale 2 (TPM_VERSION_20, il valore che la documentazione di
// TPM_DEVICE_INFO chiede di impostare); se il servizio lo rifiutasse si
// riprova con 1.
func tpmVersion() *string {
	if procTbsiGetDeviceInfo.Find() != nil {
		return nil
	}
	var first uint32
	for i, sv := range []uint32{2, 1} {
		info := tpmDeviceInfo{structVersion: sv}
		r, _, _ := procTbsiGetDeviceInfo.Call(unsafe.Sizeof(info), uintptr(unsafe.Pointer(&info)))
		code := uint32(r)
		if i == 0 {
			first = code
		}
		if code == tbsSuccess || code == tbsTPMNotFound {
			return tpmVersionOf(code, info.tpmVersion)
		}
	}
	return tpmVersionOf(first, 0)
}

// readAppraiser legge il verdetto che il controllo di compatibilità di
// Windows Update (appraiser) ha già scritto per la versione di Windows 11
// più recente. La posizione nel registro NON è documentata da Microsoft
// (si trova in fonti di terzi; i valori UpgEx e RedReason sono descritti
// nella pagina di Configuration Manager sul dashboard di Windows 11): è un
// indizio, non una verifica. Esiste solo se l'appraiser è già stato
// eseguito su questo PC.
func readAppraiser() *scan.Win11Appraiser {
	const base = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	names, _ := k.ReadSubKeyNames(0)
	k.Close()
	key, target := latestAppraiserKey(names)
	if key == "" {
		return nil
	}
	sk, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+key, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil
	}
	defer sk.Close()
	upg, _, _ := sk.GetStringValue("UpgEx")
	red, _, _ := sk.GetStringValue("RedReason")
	var at time.Time
	if st, err := sk.Stat(); err == nil {
		at = st.ModTime()
	}
	return AppraiserOf(target, upg, red, at)
}
