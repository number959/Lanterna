package autoruns

import (
	"strings"
	"testing"
)

func TestServiceHelpers(t *testing.T) {
	for in, want := range map[[2]uint32]string{{0, 0}: "boot", {1, 0}: "system", {2, 0}: "auto", {2, 1}: "delayed", {3, 0}: "manual", {4, 0}: "disabled", {9, 0}: ""} {
		if got := startName(in[0], in[1] == 1); got != want {
			t.Errorf("startName(%v) = %q", in, got)
		}
	}
	for in, want := range map[string]string{
		"": "system", "LocalSystem": "system", `NT AUTHORITY\SYSTEM`: "system",
		`NT AUTHORITY\LocalService`: "localservice", `NT AUTHORITY\Local Service`: "localservice",
		`NT AUTHORITY\NetworkService`: "networkservice", `NT Authority\Network Service`: "networkservice",
		`NT SERVICE\MSSQLSERVER`: "other", `.\anna`: "user", `UFFICIO\mario`: "user", "svc@contoso.com": "user",
	} {
		if got := accountOf(in); got != want {
			t.Errorf("accountOf(%q) = %q, atteso %q", in, got, want)
		}
	}
	if perUserBase("CDPUserSvc_4f2a1", 0xE0) != "CDPUserSvc" || perUserBase("CDPUserSvc_4f2a1", 0x20) != "CDPUserSvc_4f2a1" ||
		perUserBase("Foo_Bar", 0x60) != "Foo_Bar" || perUserBase("Servizio_", 0x60) != "Servizio_" {
		t.Error("perUserBase")
	}
	merged := mergeUserServices([]rawService{
		{Name: "CDPUserSvc_4f2a1", Display: "Connected Devices Platform User Service_4f2a1", Type: 0xE0, Running: true, Start: 2},
		{Name: "CDPUserSvc", Display: "Connected Devices Platform User Service", Type: 0x60, Start: 2, Image: `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`},
		{Name: "CDPUserSvc_99", Display: "Connected Devices Platform User Service_99", Type: 0xE0},
		{Name: "Spooler", Type: 0x110, Start: 2},
	})
	if len(merged) != 2 || merged[0].Name != "CDPUserSvc" || !merged[0].Running || merged[0].Image == "" || merged[0].Display != "Connected Devices Platform User Service" || merged[1].Name != "Spooler" {
		t.Errorf("servizi per utente: %+v", merged)
	}
}

func TestServiceItem(t *testing.T) {
	env := newFakeEnv(`C:\Program.exe`, `C:\Program Files\Vendor App\svc.exe`, `C:\Windows\System32\drivers\vendor.sys`)
	rd := testReader(env)
	for _, c := range []struct {
		raw      rawService
		cat      string
		file     string
		start    string
		account  string
		unquoted bool
		inter    int
		hijack   bool
	}{
		{rawService{Name: "Dhcp", Type: 0x20, Start: 2, Image: `C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p`, Account: `NT Authority\LocalService`, ServiceDll: `%SystemRoot%\system32\dhcpcore.dll`},
			"services", `C:\Windows\system32\dhcpcore.dll`, "auto", "localservice", false, 0, false},
		{rawService{Name: "VendorSvc", Type: 0x10, Start: 2, Delayed: true, Image: `C:\Program Files\Vendor App\svc.exe -run`},
			"services", `C:\Program Files\Vendor App\svc.exe`, "delayed", "system", true, 1, true},
		{rawService{Name: "Quoted", Type: 0x10, Start: 3, Image: `"C:\Program Files\Vendor App\svc.exe" -run`, Account: `.\anna`},
			"services", `C:\Program Files\Vendor App\svc.exe`, "manual", "user", false, 0, false},
		// Senza virgolette dopo l'espansione: C:\Program.exe intercetta anche questo.
		{rawService{Name: "Exp", Type: 0x10, Start: 4, Image: `%ProgramFiles%\Other App\o.exe`},
			"services", `C:\Program Files\Other App\o.exe`, "disabled", "system", true, 1, true},
		{rawService{Name: "NoInt", Type: 0x10, Start: 2, Image: `D:\Vendor Apps\a.exe`},
			"services", `D:\Vendor Apps\a.exe`, "auto", "system", true, 0, false},
		{rawService{Name: "vendor", Type: 0x1, Start: 1, Image: `\SystemRoot\System32\drivers\vendor.sys`, Account: `\Driver\vendor`},
			"drivers", `C:\Windows\System32\drivers\vendor.sys`, "system", "", false, 0, false},
		{rawService{Name: "rel", Type: 0x1, Start: 0, Image: `System32\drivers\rel.sys`}, "drivers", `C:\Windows\System32\drivers\rel.sys`, "boot", "", false, 0, false},
		{rawService{Name: "nt", Type: 0x2, Start: 3, Image: `\??\C:\Vendor Tools\fs.sys`}, "drivers", `C:\Vendor Tools\fs.sys`, "manual", "", false, 0, false},
		{rawService{Name: "noimg", Type: 0x1, Start: 3}, "drivers", `C:\Windows\System32\drivers\noimg.sys`, "manual", "", false, 0, false},
		{rawService{Name: "OneSyncSvc", Type: 0x60, Start: 2, Image: `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`}, "services", `C:\Windows\system32\svchost.exe`, "auto", "user", false, 0, false},
	} {
		it := rd.serviceItem(c.raw)
		e := it.entry
		if e.Category != c.cat || it.file != c.file || e.Start != c.start || e.Account != c.account || e.Unquoted != c.unquoted || e.Interceptors != c.inter || it.hijack != c.hijack {
			t.Errorf("%s: %+v (file %q, dirottamento %v)", c.raw.Name, e, it.file, it.hijack)
		}
		if e.Enabled != (c.start != "disabled") || !strings.HasSuffix(e.Location, `\Services\`+c.raw.Name) || e.Name != c.raw.Name {
			t.Errorf("%s: attivo %v, chiave %q", c.raw.Name, e.Enabled, e.Location)
		}
	}
	// Configurazione non letta: modo di avvio sconosciuto, non «boot», e
	// account non letto, non LocalSystem (decisione comune n. 4).
	if it := rd.serviceItem(rawService{Name: "x", Type: 0x10, Start: ^uint32(0)}); it.entry.Start != "" || !it.entry.Enabled || it.file != "" || it.entry.Account != "" {
		t.Errorf("configurazione non letta: %+v", it)
	}
	// Driver con la configurazione non letta: il percorso non si indovina
	// (il .sys può stare in drivers\wd o in DriverStore).
	if it := rd.serviceItem(rawService{Name: "WdFilter", Type: 0x2, Start: ^uint32(0)}); it.file != "" || it.entry.Category != "drivers" {
		t.Errorf("driver con la configurazione non letta: %+v", it)
	}
	// Servizio senza nome visualizzato: nome e chiave passano dal pulitore.
	if it := rd.serviceItem(rawService{Name: "Backup anna", Type: 0x10, Start: 3, Image: `C:\x\b.exe`}); strings.Contains(it.entry.Name+it.entry.Location, "anna") {
		t.Errorf("nome dell'utente nel servizio: %+v", it.entry)
	}
	// Servizio che avvia un interprete con un comando scritto per intero.
	it := rd.serviceItem(rawService{Name: "ps", Type: 0x10, Start: 2, Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c "x"`})
	if !it.interpreted {
		t.Errorf("servizio con comando interpretato: %+v", it)
	}
}
