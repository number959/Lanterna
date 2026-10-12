//go:build windows

package winapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"lanterna/internal/scan"
)

const createNoWindow = 0x08000000

// runHidden esegue un comando di sistema senza aprire finestre di console.
func runHidden(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Elevated indica se il programma gira come amministratore.
func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// OSDescription descrive il sistema, segnalando se si tratta di Wine.
func OSDescription() string {
	v := windows.RtlGetVersion()
	name := "Windows 10"
	if v.MajorVersion == 10 && v.BuildNumber >= 22000 {
		name = "Windows 11"
	} else if v.MajorVersion != 10 {
		name = fmt.Sprintf("Windows %d.%d", v.MajorVersion, v.MinorVersion)
	}
	desc := fmt.Sprintf("%s (build %d)", name, v.BuildNumber)
	if p := windows.NewLazySystemDLL("ntdll.dll").NewProc("wine_get_version"); p.Find() == nil {
		r, _, _ := p.Call()
		if r != 0 {
			// r punta a una stringa statica di ntdll, fuori dalla memoria gestita da Go.
			ver := windows.BytePtrToString(*(**byte)(unsafe.Pointer(&r)))
			desc = fmt.Sprintf("Wine %s, emula %s", ver, desc)
		} else {
			desc = "Wine, emula " + desc
		}
	}
	return desc
}

type psProfile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type psResult struct {
	Profiles   []psProfile `json:"profiles"`
	Categories []string    `json:"categories"`
}

const psFirewall = `$ErrorActionPreference='Stop';` +
	`$p=@(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { [pscustomobject]@{name="$($_.Name)"; enabled=("$($_.Enabled)" -eq 'True')} });` +
	`$c=@(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { "$($_.NetworkCategory)" });` +
	`ConvertTo-Json -Compress -Depth 3 -InputObject ([pscustomobject]@{profiles=$p; categories=$c})`

// Firewall legge lo stato dei profili di Windows Defender Firewall e quale
// profilo è in uso. Prima PowerShell (dati effettivi, criteri inclusi),
// poi il registro come riserva.
func Firewall(ctx context.Context) (*scan.FirewallData, error) {
	out, err := runHidden(ctx, 15*time.Second, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psFirewall)
	if err == nil {
		if i := strings.Index(out, "{"); i >= 0 {
			var r psResult
			if json.Unmarshal([]byte(strings.TrimSpace(out[i:])), &r) == nil && len(r.Profiles) > 0 {
				active := map[string]bool{}
				for _, c := range r.Categories {
					switch strings.ToLower(c) {
					case "private":
						active["private"] = true
					case "public":
						active["public"] = true
					case "domainauthenticated":
						active["domain"] = true
					}
				}
				fw := &scan.FirewallData{Source: "powershell"}
				for _, p := range r.Profiles {
					name := strings.ToLower(p.Name)
					if name != "domain" && name != "private" && name != "public" {
						continue
					}
					en := p.Enabled
					fw.Profiles = append(fw.Profiles, scan.FirewallProfile{Name: name, Enabled: &en, Active: active[name]})
				}
				return fw, nil
			}
		}
	}
	return firewallRegistry()
}

func firewallRegistry() (*scan.FirewallData, error) {
	profiles := []struct{ name, policy, local string }{
		{"domain", "DomainProfile", "DomainProfile"},
		{"private", "PrivateProfile", "StandardProfile"},
		{"public", "PublicProfile", "PublicProfile"},
	}
	fw := &scan.FirewallData{Source: "registry"}
	found := false
	for _, p := range profiles {
		var enabled *bool
		for _, path := range []string{
			`SOFTWARE\Policies\Microsoft\WindowsFirewall\` + p.policy,
			`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\` + p.local,
		} {
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			v, _, err := k.GetIntegerValue("EnableFirewall")
			k.Close()
			if err == nil {
				b := v != 0
				enabled = &b
				found = true
				break
			}
		}
		fw.Profiles = append(fw.Profiles, scan.FirewallProfile{Name: p.name, Enabled: enabled})
	}
	if !found {
		return nil, fmt.Errorf("stato del firewall non leggibile (servizio non presente?)")
	}
	return fw, nil
}
