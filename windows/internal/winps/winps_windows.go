//go:build windows

package winps

import (
	"context"
	"os"
	"os/exec"
	"syscall"
)

const createNoWindow = 0x08000000

// Command prepara powershell.exe con lo script indicato, senza finestre di
// console, senza profilo utente e con l'ambiente di Env.
func Command(ctx context.Context, script string, extraEnv ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, Exe(os.Getenv("SystemRoot")), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.Env = Env(os.Environ(), extraEnv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd
}
