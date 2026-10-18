//go:build windows

package defender

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"lanterna/internal/pcinfo"
)

const createNoWindow = 0x08000000

// tool trova MpCmdRun.exe nella cartella di Defender.
func tool() (string, error) {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}
	p := filepath.Join(pf, "Windows Defender", "MpCmdRun.exe")
	if _, err := os.Stat(p); err != nil {
		return "", ErrUnavailable
	}
	return p, nil
}

// Available dice se lo strumento di Defender è presente.
func Available() error {
	_, err := tool()
	return err
}

func command(ctx context.Context, path string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return cmd
}

// Run esegue l'azione e attende la fine. Se ctx viene annullato durante una
// scansione, la scansione viene fermata con l'apposito comando di Defender
// (terminare il programma non basterebbe: la scansione la esegue il servizio).
func Run(ctx context.Context, action string) (*Result, error) {
	args, err := Args(action)
	if err != nil {
		return nil, err
	}
	path, err := tool()
	if err != nil {
		return nil, err
	}
	start := time.Now()
	cmd := command(ctx, path, args...)
	cmd.Cancel = func() error {
		if action != Update {
			stop, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = command(stop, path, CancelArgs...).Run()
		}
		return cmd.Process.Kill()
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return nil, err
		}
		code = ee.ExitCode()
	}
	if err := CheckExit(action, code, string(out)); err != nil {
		return nil, err
	}
	res := &Result{Action: action, StartedAt: start.UTC().Format(time.RFC3339), DurationMs: time.Since(start).Milliseconds()}
	sctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if d, threats, err := pcinfo.DefenderStatus(sctx); err == nil {
		res.Defender, res.Threats = d, threats
		res.NewThreats = NewSince(threats, start)
	}
	res.Message = Message(action, res.NewThreats, res.Defender)
	return res, nil
}
