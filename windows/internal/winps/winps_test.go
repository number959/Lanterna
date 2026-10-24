package winps

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestEnvDropsModulePath(t *testing.T) {
	in := []string{
		`PATH=C:\Windows\system32`,
		`PSModulePath=C:\Program Files\PowerShell\7\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules`,
		`psmodulepath=altro`,
		`PSModulePathX=resta`,
		`SystemRoot=C:\Windows`,
	}
	got := Env(in, `POLARIS_FILE=C:\x.exe`)
	want := []string{`PATH=C:\Windows\system32`, `PSModulePathX=resta`, `SystemRoot=C:\Windows`, `POLARIS_FILE=C:\x.exe`}
	if !slices.Equal(got, want) {
		t.Fatalf("Env = %q, atteso %q", got, want)
	}
	if in[1] == "" || len(in) != 5 {
		t.Fatal("Env non deve modificare l'ambiente ricevuto")
	}
}

func TestExe(t *testing.T) {
	if got := Exe(""); got != "powershell.exe" {
		t.Fatalf("Exe(\"\") = %q", got)
	}
	got := Exe(`C:\Windows`)
	if !strings.HasSuffix(filepath.ToSlash(got), "System32/WindowsPowerShell/v1.0/powershell.exe") {
		t.Fatalf("Exe = %q", got)
	}
}

// Processo figlio dei test: scrive sullo standard error ed esce con errore,
// come PowerShell quando uno script si ferma.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("WINPS_HELPER") == "" {
		return
	}
	fmt.Fprint(os.Stderr, os.Getenv("WINPS_HELPER"))
	os.Exit(1)
}

func failing(t *testing.T, stderr string) error {
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), "WINPS_HELPER="+stderr)
	out, err := cmd.Output()
	if err == nil || len(out) != 0 {
		t.Fatalf("il processo figlio doveva fallire senza output: %v %q", err, out)
	}
	return err
}

func TestExplain(t *testing.T) {
	plain := errors.New("scaduto")
	if Explain(plain) != plain {
		t.Fatal("un errore che non viene da un processo resta com'è")
	}
	got := Explain(failing(t, "\r\nGet-AuthenticodeSignature : The module could not be loaded.\r\nAt line:3 char:6\r\n")).Error()
	if !strings.HasPrefix(got, "exit status 1: ") || !strings.HasSuffix(got, ": Get-AuthenticodeSignature : The module could not be loaded.") {
		t.Fatalf("Explain = %q", got)
	}
	got = Explain(failing(t, strings.Repeat("è", 300))).Error()
	if !strings.HasSuffix(got, ": "+strings.Repeat("è", 200)+"…") {
		t.Fatalf("riga lunga non accorciata: %q", got)
	}
}
