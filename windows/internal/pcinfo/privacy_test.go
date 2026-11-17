package pcinfo

import (
	"strings"
	"testing"
)

func TestSanitizeCommand(t *testing.T) {
	p := `C:\Users\Mario Rossi`
	for in, want := range map[string]string{
		`"C:\Users\Mario Rossi\AppData\Local\Discord\Update.exe" --processStart Discord.exe`: `"%USERPROFILE%\AppData\Local\Discord\Update.exe" --processStart Discord.exe`,
		`c:\users\mario rossi\app.exe --log c:\users\MARIO ROSSI\log.txt`:                    `%USERPROFILE%\app.exe --log %USERPROFILE%\log.txt`,
		`"C:\Program Files\App\app.exe" /background`:                                         `"C:\Program Files\App\app.exe" /background`,
		`  C:\Users\Mario Rossi  `:                                                           `%USERPROFILE%`,
		// Barre normali e raddoppiate (alcuni installatori le scrivono così).
		`javaw -jar C:/Users/Mario Rossi/app.jar`:     `javaw -jar %USERPROFILE%/app.jar`,
		`C:\\Users\\Mario Rossi\\AppData\\x.exe`:      `%USERPROFILE%\\AppData\\x.exe`,
		`'C:\Users\Mario Rossi'; Remove-Item -WhatIf`: `'%USERPROFILE%'; Remove-Item -WhatIf`,
	} {
		if got := SanitizeCommand(in, p); got != want {
			t.Errorf("SanitizeCommand(%q)=%q, atteso %q", in, got, want)
		}
	}
	if got := SanitizeCommand(`C:\Users\Mario Rossi\x.exe`, p+`\`); got != `%USERPROFILE%\x.exe` {
		t.Errorf("barra finale nel profilo: %q", got)
	}
	// Lettere che in minuscolo cambiano lunghezza in byte prima del percorso:
	// il nome non deve passare, nemmeno in parte.
	for in, want := range map[string]string{
		`İİ C:\Users\Mario Rossi\x.exe`:          `İİ %USERPROFILE%\x.exe`,
		`İ "C:\Users\luca\a.exe" Ⱥ C:\Users\x\b`: `İ "C:\Users\‹utente›\a.exe" Ⱥ C:\Users\‹utente›\b`,
		`K C:\USERS\MARIO ROSSI\y.exe`:           `K %USERPROFILE%\y.exe`,
	} {
		if got := SanitizeCommand(in, p); got != want {
			t.Errorf("SanitizeCommand(%q)=%q, atteso %q", in, got, want)
		}
	}
	if got := SanitizeCommand(`C:\x.exe`, ""); got != `C:\x.exe` {
		t.Errorf("profilo vuoto: %q", got)
	}
	// Altri utenti, nomi che iniziano allo stesso modo, cartelle comuni, altre
	// unità e altre forme della cartella dei profili.
	a := `C:\Users\anna`
	for in, want := range map[string]string{
		`C:\Users\luigi\Downloads\setup.msi`:                            `C:\Users\‹utente›\Downloads\setup.msi`,
		`C:\Users\annabella\Desktop\x.exe`:                              `C:\Users\‹utente›\Desktop\x.exe`,
		`"C:\Users\Anna\app.exe" "C:\Users\Luigi"`:                      `"%USERPROFILE%\app.exe" "C:\Users\‹utente›"`,
		`C:\Users\Public\Documents\x.txt`:                               `C:\Users\Public\Documents\x.txt`,
		`C:\Users\%USERNAME%\x.txt`:                                     `C:\Users\%USERNAME%\x.txt`,
		`C:\Users\`:                                                     `C:\Users\`,
		`D:\Users\luigi\x.exe`:                                          `D:\Users\‹utente›\x.exe`,
		`javaw -jar C:/Users/luca/app.jar`:                              `javaw -jar C:/Users/‹utente›/app.jar`,
		`C:\Windows.old\Users\luca\x.exe`:                               `C:\Windows.old\Users\‹utente›\x.exe`,
		`%SystemDrive%\Users\luca\x.exe`:                                `%SystemDrive%\Users\‹utente›\x.exe`,
		`\\localhost\C$\Users\luca\x.exe`:                               `\\localhost\C$\Users\‹utente›\x.exe`,
		`C:\Documents and Settings\luca\x.exe`:                          `C:\Documents and Settings\‹utente›\x.exe`,
		`\\?\C:\Users\luca\x.exe`:                                       `\\?\C:\Users\‹utente›\x.exe`,
		`%HOMEDRIVE%\Users\luca\x.exe`:                                  `%HOMEDRIVE%\Users\‹utente›\x.exe`,
		`\Device\HarddiskVolume3\Users\luca\x.exe`:                      `\Device\HarddiskVolume3\Users\‹utente›\x.exe`,
		`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12\Users\luca\x`: `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12\Users\‹utente›\x`,
		`\Device\Harddisk\Users\luca\x.exe`:                             `\Device\Harddisk\Users\luca\x.exe`,
		// Un secondo percorso subito dopo il nome: non sparisce e non resta in chiaro.
		`robocopy C:\Users\luca C:\Users\gino\Backup /MIR`: `robocopy C:\Users\‹utente› C:\Users\‹utente›\Backup /MIR`,
		`robocopy C:\Users\luca \\nas\backup /MIR`:         `robocopy C:\Users\‹utente› \\nas\backup /MIR`,
		"cmd /c C:\\Users\\luca\tC:\\Users\\gino":          "cmd /c C:\\Users\\‹utente›\tC:\\Users\\‹utente›",
		`a.exe C:\Users\luca;C:\Users\gino,x`:              `a.exe C:\Users\‹utente›;C:\Users\‹utente›,x`,
		`a.exe C:\Users\luca|more`:                         `a.exe C:\Users\‹utente›|more`,
		`a.exe C:\Users\luca /s`:                           `a.exe C:\Users\‹utente› /s`,
		// Cognomi con l'apostrofo: interi; l'apostrofo che chiude il percorso resta.
		`C:\Users\Lucia Dell'Acqua\x.exe`: `C:\Users\‹utente›\x.exe`,
		`'C:\Users\luca\x.ps1'`:           `'C:\Users\‹utente›\x.ps1'`,
		`'C:\Users\luca'`:                 `'C:\Users\‹utente›'`,
		// Una cartella «Users» che non è quella dei profili resta.
		`C:\App\Users\config.ini`: `C:\App\Users\config.ini`,
		`XD:\Users\luca`:          `XD:\Users\luca`,
	} {
		if got := SanitizeCommand(in, a); got != want {
			t.Errorf("SanitizeCommand(%q)=%q, atteso %q", in, got, want)
		}
	}
	// Il proprio profilo con l'apostrofo: %USERPROFILE%, senza pezzi del cognome.
	ap := `C:\Users\Marco D'Amico`
	for in, want := range map[string]string{
		`C:\Users\Marco D'Amico\AppData\Local\x.exe`:       `%USERPROFILE%\AppData\Local\x.exe`,
		`robocopy "C:\Users\Marco D'Amico" D:\Backup /MIR`: `robocopy "%USERPROFILE%" D:\Backup /MIR`,
		`'C:\Users\Marco D'Amico'`:                         `'%USERPROFILE%'`,
	} {
		if got := SanitizeCommand(in, ap); got != want {
			t.Errorf("SanitizeCommand(%q)=%q, atteso %q", in, got, want)
		}
	}
	// Con un profilo in una cartella che non è una radice di utenti non si
	// maschera nient'altro sotto quella radice, ma i profili veri sì.
	if got := SanitizeCommand(`C:\Program Files\x.exe C:\anna\y`, `C:\anna`); got != `C:\Program Files\x.exe %USERPROFILE%\y` {
		t.Errorf("radice C: %q", got)
	}
	if got := SanitizeCommand(`C:\Users\luca\x.exe`, `C:\anna`); got != `C:\Users\‹utente›\x.exe` {
		t.Errorf("radice C:, profilo di un altro utente: %q", got)
	}
	// Una seconda pulizia non cambia nulla.
	for _, in := range []string{`C:\Users\luca\x.exe C:\Users\anna\y`, `C:\Users\Public\a`} {
		once := SanitizeCommand(in, a)
		if twice := SanitizeCommand(once, a); twice != once {
			t.Errorf("seconda pulizia di %q: %q → %q", in, once, twice)
		}
	}
}

func TestMaskPublicIPs(t *testing.T) {
	for in, want := range map[string]string{
		`mstsc.exe /v:203.0.113.5`:                           `mstsc.exe /v:‹indirizzo›`,
		`plink.exe -R 3389:localhost:3389 admin@203.0.113.5`: `plink.exe -R 3389:localhost:3389 admin@‹indirizzo›`,
		`rclone sync D:\Dati sftp://198.51.100.20/backup`:    `rclone sync D:\Dati sftp://‹indirizzo›/backup`,
		`net use Z: \\203.0.113.7\dati`:                      `net use Z: \\‹indirizzo›\dati`,
		`agent.exe --server=8.8.8.8:443 --peer "1.1.1.1"`:    `agent.exe --server=‹indirizzo›:443 --peer "‹indirizzo›"`,
		`ssh.exe -6 [2a00:1450:4002:41b::200e]:22`:           `ssh.exe -6 [‹indirizzo›]:22`,
		`ping 2001:db8::1`:                                   `ping ‹indirizzo›`,
		`x.exe ::ffff:203.0.113.5`:                           `x.exe ::ffff:‹indirizzo›`,
		// Operatori della riga di comando, a capo, fine della frase.
		`ping -n 1 203.0.113.5>nul`:          `ping -n 1 ‹indirizzo›>nul`,
		`cmd /c "ping 203.0.113.5|find TTL"`: `cmd /c "ping ‹indirizzo›|find TTL"`,
		`x.exe 203.0.113.5&y.exe`:            `x.exe ‹indirizzo›&y.exe`,
		`curl http://203.0.113.5?x=1`:        `curl http://‹indirizzo›?x=1`,
		`curl http://203.0.113.5#x`:          `curl http://‹indirizzo›#x`,
		`<203.0.113.5>`:                      `<‹indirizzo›>`,
		"righe\n203.0.113.5\r\n":             "righe\n‹indirizzo›\r\n",
		`Connessione a 203.0.113.5.`:         `Connessione a ‹indirizzo›.`,
		`ping 2001:db8::1%12`:                `ping ‹indirizzo›%12`,
		// Condivisioni scritte in altre forme: \\?\UNC, WebDAV.
		`\\?\UNC\203.0.113.5\share\x.exe`:        `\\?\UNC\‹indirizzo›\share\x.exe`,
		`\\203.0.113.5@SSL\DavWWWRoot\x.exe`:     `\\‹indirizzo›@SSL\DavWWWRoot\x.exe`,
		`\\203.0.113.5@SSL@443\DavWWWRoot\x.exe`: `\\‹indirizzo›@SSL@443\DavWWWRoot\x.exe`,
		// Indirizzi della rete locale e speciali: restano, servono alla diagnosi.
		`mstsc.exe /v:192.168.1.20 /v:10.0.0.5 /v:172.16.0.1`:        `mstsc.exe /v:192.168.1.20 /v:10.0.0.5 /v:172.16.0.1`,
		`x.exe 127.0.0.1 100.64.1.2 169.254.1.1 0.0.0.0 224.0.0.251`: `x.exe 127.0.0.1 100.64.1.2 169.254.1.1 0.0.0.0 224.0.0.251`,
		`x.exe fe80::1 fd12:3456::1 ::1 ::`:                          `x.exe fe80::1 fd12:3456::1 ::1 ::`,
		`\\192.168.1.10\condivisa\gest.exe`:                          `\\192.168.1.10\condivisa\gest.exe`,
		// Versioni nei percorsi e nei nomi, orari, MAC, PowerShell: restano.
		`C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.195.39\x.exe`: `C:\Program Files (x86)\Microsoft\EdgeUpdate\1.3.195.39\x.exe`,
		`setup-8.8.8.8.exe`:                        `setup-8.8.8.8.exe`,
		`"C:\\App\\EdgeUpdate\\1.3.195.39\\x.exe"`: `"C:\\App\\EdgeUpdate\\1.3.195.39\\x.exe"`,
		`"\\203.0.113.7\dati\x.exe"`:               `"\\‹indirizzo›\dati\x.exe"`,
		`app 1.2.3.4.5`:                            `app 1.2.3.4.5`,
		`app 1.2.3.4.exe`:                          `app 1.2.3.4.exe`,
		`C:\App\1.2.3.4@x\a.exe`:                   `C:\App\1.2.3.4@x\a.exe`,
		`schtasks /st 10:30:45`:                    `schtasks /st 10:30:45`,
		`aa:bb:cc:dd:ee:ff`:                        `aa:bb:cc:dd:ee:ff`,
		`powershell [IO.File]::ReadAllText('a')`:   `powershell [IO.File]::ReadAllText('a')`,
		`std::cout`:                                `std::cout`,
		``:                                         ``,
	} {
		if got := MaskPublicIPs(in); got != want {
			t.Errorf("MaskPublicIPs(%q) = %q, atteso %q", in, got, want)
		}
	}
}

func TestCleaner(t *testing.T) {
	c := Cleaner{Profile: `C:\Users\anna`, User: "anna"}
	for in, want := range map[string]string{
		`GoogleUpdateTaskUserS-1-5-21-1004336348-1177238915-682003330-1001UA`: `GoogleUpdateTaskUserS-1-5-21-…-1001UA`,
		// SID degli account Microsoft Entra ID: tutte e quattro le parti sono
		// l'ID dell'oggetto della persona.
		`OneDrive Standalone Update Task-S-1-12-1-1234567890-2345678901-3456789012-4567890123`: `OneDrive Standalone Update Task-S-1-12-1-…`,
		`GoogleUpdateTaskUserS-1-12-1-1-2-3-4Core`:                                             `GoogleUpdateTaskUserS-1-12-1-…Core`,
		`C:\$Recycle.Bin\S-1-12-1-11-22-33-44\$R1.exe`:                                         `C:\$Recycle.Bin\S-1-12-1-…\$R1.exe`,
		`Backup di anna`:                     `Backup di ‹utente›`,
		`Notifica mario.rossi@example.it ok`: `Notifica ‹e-mail› ok`,
		`Assistenza 203.0.113.5`:             `Assistenza ‹indirizzo›`,
	} {
		if got := c.Text(in); got != want {
			t.Errorf("Text(%q) = %q, atteso %q", in, got, want)
		}
	}
	// Cartelle reindirizzate su un server o col nome dell'account fuori da
	// C:\Users, il Cestino con il SID: il nome dell'utente e il SID non escono.
	m := Cleaner{Profile: `C:\Users\mario.rossi`, User: "mario.rossi"}
	for _, in := range []string{
		`\\srv\home$\mario.rossi\Desktop\x.exe`,
		`\\srv01\profili$\Mario.Rossi\AppData\Roaming\Zoom\bin\Zoom.exe`,
		`D:\mario.rossi\x.exe`,
		`D:\Users\mario.rossi\x.exe`,
		`C:/Users/mario.rossi/x.exe`,
	} {
		if got := m.Path(in); strings.Contains(strings.ToLower(got), "mario.rossi") {
			t.Errorf("Path(%q) = %q: resta il nome dell'utente", in, got)
		}
	}
	if got := m.Path(`C:\$Recycle.Bin\S-1-5-21-1111-2222-3333-1001\$RAB12CD.exe`); got != `C:\$Recycle.Bin\S-1-5-21-…-1001\$RAB12CD.exe` {
		t.Errorf("Cestino: %q", got)
	}
	if got := m.Path(`C:\Users\mario.rossi\AppData\x.exe /v:203.0.113.5`); got != `%USERPROFILE%\AppData\x.exe /v:‹indirizzo›` {
		t.Errorf("profilo e indirizzo: %q", got)
	}
	// Una seconda pulizia (l'avvio automatico ripassa Text sui percorsi) non cambia nulla.
	for _, in := range []string{`C:\Users\luca\x.exe S-1-12-1-1-2-3-4 /v:203.0.113.5 anna@example.it`, `\\srv\home$\mario.rossi\x.exe`} {
		once := m.Path(in)
		if twice := m.Text(once); twice != once {
			t.Errorf("seconda pulizia di %q: %q → %q", in, once, twice)
		}
	}
}
