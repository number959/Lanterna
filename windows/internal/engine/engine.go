// Package engine esegue nell'exe lo stesso motore di analisi JavaScript
// usato dall'interfaccia (core/src/engine, compilato in engine.js), tramite
// l'interprete goja. Così il rapporto da riga di comando e quello grafico
// sono identici per costruzione.
package engine

import (
	"fmt"
	"io/fs"
	"sync"

	"github.com/dop251/goja"

	"lanterna/internal/assets"
)

type Engine struct {
	mu      sync.Mutex
	vm      *goja.Runtime
	version string
	report  goja.Callable
	analyze goja.Callable
}

// Load compila engine.js da src (o dalle risorse incorporate se src è nil).
func Load(src []byte) (*Engine, error) {
	if src == nil {
		b, err := fs.ReadFile(assets.Web(), "engine.js")
		if err != nil {
			return nil, fmt.Errorf("motore di analisi non incluso nella build: %w", err)
		}
		src = b
	}
	vm := goja.New()
	if _, err := vm.RunScript("engine.js", string(src)); err != nil {
		return nil, fmt.Errorf("caricamento del motore: %w", err)
	}
	obj := vm.Get("LanternaEngine")
	if obj == nil || goja.IsUndefined(obj) {
		return nil, fmt.Errorf("engine.js non definisce LanternaEngine")
	}
	o := obj.ToObject(vm)
	e := &Engine{vm: vm, version: o.Get("version").String()}
	var ok bool
	if e.report, ok = goja.AssertFunction(o.Get("reportText")); !ok {
		return nil, fmt.Errorf("LanternaEngine.reportText mancante")
	}
	if e.analyze, ok = goja.AssertFunction(o.Get("analyzeJson")); !ok {
		return nil, fmt.Errorf("LanternaEngine.analyzeJson mancante")
	}
	return e, nil
}

func (e *Engine) Version() string { return e.version }

// Report produce il rapporto testuale a partire dal JSON di uno scan.
func (e *Engine) Report(scanJSON []byte, verbose bool) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, err := e.report(goja.Undefined(), e.vm.ToValue(string(scanJSON)), e.vm.ToValue(verbose))
	if err != nil {
		return "", err
	}
	return v.String(), nil
}

// Analyze restituisce l'analisi completa in JSON.
func (e *Engine) Analyze(scanJSON []byte) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	v, err := e.analyze(goja.Undefined(), e.vm.ToValue(string(scanJSON)))
	if err != nil {
		return nil, err
	}
	return []byte(v.String()), nil
}
