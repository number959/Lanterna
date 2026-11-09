//go:build windows

package pcinfo

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/registry"

	"lanterna/internal/scan"
	"lanterna/internal/winevt"
	"lanterna/internal/winps"
)

// readBoot legge avvii e spegnimenti misurati da Windows e l'ultimo tempo
// del firmware.
func readBoot(ctx context.Context) *scan.BootPerf {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	events, err := winevt.Query(ctx, BootChannel, winevt.XPath(BootIDs, BootDays), 2000)
	b := BootFrom(events, BootDays)
	if err != nil && len(events) == 0 {
		b.Channel = ChannelState(err)
	}
	b.FirmwareMs = firmwarePost()
	return b
}

// firmwarePost legge FwPOSTTime, il tempo del firmware all'ultima accensione
// (lo stesso dato di "Ultimo tempo BIOS" in Gestione attività).
func firmwarePost() *int64 {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Power`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("FwPOSTTime")
	if err != nil || v == 0 || v > 600000 {
		return nil
	}
	ms := int64(v)
	return &ms
}

// readApps legge arresti e blocchi dei programmi del registro Applicazione e
// le impostazioni di Segnalazione errori Windows.
func readApps(ctx context.Context) *scan.AppFailures {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	events, err := winevt.Query(ctx, AppChannel, winevt.XPath(AppIDs, AppDays, AppProviders...), 3000)
	usersRoot := ""
	if p := os.Getenv("USERPROFILE"); p != "" {
		usersRoot = filepath.Dir(p)
	}
	d := AppsFrom(events, AppDays, usersRoot, os.Getenv("SystemRoot"))
	if err != nil && len(events) == 0 {
		d.Channel = ChannelState(err)
	}
	d.Wer = werSettings()
	return d
}

func dword(k registry.Key, name string) (uint64, bool) {
	v, _, err := k.GetIntegerValue(name)
	return v, err == nil
}

// werSettings legge le impostazioni di Segnalazione errori Windows (computer,
// criteri di gruppo e utente), senza modificarle.
func werSettings() *scan.WerSettings {
	w := &scan.WerSettings{}
	read := func(root registry.Key, path string, policy bool) {
		k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
		if err != nil {
			return
		}
		defer k.Close()
		for name, dst := range map[string]*bool{"Disabled": &w.Disabled, "DontShowUI": &w.DontShowUI, "LoggingDisabled": &w.LoggingDisabled} {
			if v, ok := dword(k, name); ok {
				if v != 0 {
					*dst = true
				}
				if policy {
					w.Policy = true
				}
			}
		}
		if s, _, err := k.GetStringValue("CorporateWERServer"); err == nil && s != "" {
			w.CorporateServer = true
		}
	}
	read(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\Windows Error Reporting`, false)
	read(registry.CURRENT_USER, `Software\Microsoft\Windows\Windows Error Reporting`, false)
	read(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting`, true)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps`, registry.QUERY_VALUE); err == nil {
		w.LocalDumps = true
		k.Close()
	}
	return w
}

// reliabilityWMI legge WMIEnable, che accende o spegne i dati di
// Monitoraggio affidabilità; nil se il valore non c'è.
func reliabilityWMI() *bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Reliability Analysis\WMI`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, ok := dword(k, "WMIEnable")
	if !ok {
		return nil
	}
	on := v != 0
	return &on
}

// runHealth esegue HealthScript con un tempo massimo.
func runHealth(ctx context.Context) (*healthOut, error) {
	return runHealthScript(ctx, HealthScript)
}

// runReliability esegue ReliabilityScript con un tempo massimo.
func runReliability(ctx context.Context) (*healthOut, error) {
	return runHealthScript(ctx, ReliabilityScript)
}

func runHealthScript(ctx context.Context, script string) (*healthOut, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	out, err := winps.Command(ctx, script).Output()
	if err != nil && len(out) == 0 {
		var ee *exec.Error
		if errors.As(err, &ee) {
			return nil, errors.New("non disponibile")
		}
		return nil, winps.Explain(err)
	}
	return parseHealth(string(out))
}
