//go:build windows

package autoruns

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"lanterna/internal/winps"
)

// scriptTimeout è il tempo massimo di ciascuno script PowerShell, come gli
// altri script dell'agente (pcinfo).
const scriptTimeout = 40 * time.Second

// runScript esegue uno script in sola lettura con Windows PowerShell
// (winps: dalla cartella di sistema, senza profilo e senza moduli
// ereditati), con un tempo massimo.
func runScript(ctx context.Context, script string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, scriptTimeout)
	defer cancel()
	out, err := winps.Command(ctx, script).Output()
	if err != nil && len(out) == 0 {
		var ee *exec.Error
		if errors.As(err, &ee) {
			return nil, errors.New("PowerShell non disponibile")
		}
		if ctx.Err() != nil {
			return nil, errors.New("tempo scaduto")
		}
		return nil, winps.Explain(err)
	}
	return out, nil
}

// readTasks legge le attività pianificate con TasksScript.
func readTasks(ctx context.Context, rd reader) sourceResult {
	out, err := runScript(ctx, TasksScript)
	if err != nil {
		return sourceResult{err: fmt.Errorf("attività pianificate: %w", err)}
	}
	t, err := parseTasks(out)
	if err != nil {
		return sourceResult{err: fmt.Errorf("attività pianificate: %w", err)}
	}
	return rd.tasksSource(t, time.Local, comDLL)
}

// readWMI legge le sottoscrizioni WMI permanenti con WMIScript.
func readWMI(ctx context.Context, rd reader) sourceResult {
	out, err := runScript(ctx, WMIScript)
	if err != nil {
		return sourceResult{err: fmt.Errorf("sottoscrizioni WMI: %w", err)}
	}
	w, err := parseWMI(out)
	if err != nil {
		return sourceResult{err: fmt.Errorf("sottoscrizioni WMI: %w", err)}
	}
	var res sourceResult
	for ns, code := range w.Errors {
		if deniedCode(code) {
			res.denied = []string{"wmi"}
		} else if ns == "root/subscription" {
			res.err = fmt.Errorf("sottoscrizioni WMI: %s non leggibile (%s)", ns, code)
		}
	}
	for _, c := range w.Items {
		res.items = append(res.items, rd.consumerItem(c))
	}
	return res
}
