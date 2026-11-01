package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"lanterna/internal/crash"
	"lanterna/internal/scan"
)

// runCrashes mostra le schermate blu salvate da Windows (come BlueScreenView):
// codice di arresto, parametri, driver indicato come indizio e impostazioni
// dei dump. Legge soltanto: non modifica impostazioni e non sposta file.
func runCrashes(args []string) error {
	fs := flag.NewFlagSet("crashes", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("argomento non previsto: %s", fs.Arg(0))
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	d, err := crash.Read(ctx)
	if d == nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(d, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	printCrashes(d, time.Local)
	return nil
}

// Nomi dei valori di CrashDumpEnabled e dei tipi di dump.
var dumpEnabledText = map[int]string{0: "nessun file", 1: "dump completo della memoria", 2: "dump del kernel", 3: "dump piccolo (minidump)", 7: "dump automatico"}

var dumpTypeText = map[string]string{
	"triage":        "dump piccolo (minidump)",
	"kernel":        "dump del kernel",
	"full":          "dump completo",
	"header":        "solo intestazione",
	"bitmap-full":   "dump completo",
	"bitmap-kernel": "dump del kernel",
	"automatic":     "dump automatico",
	"kernel-user":   "dump del kernel e dei processi",
	"unknown":       "tipo non riconosciuto",
}

var limitedText = map[string]string{
	"not-triage":   "solo intestazione",
	"32bit":        "dump a 32 bit: solo intestazione",
	"too-large":    "file molto grande: solo intestazione",
	"inconsistent": "dati del minidump incoerenti: solo intestazione",
}

func settingsText(s *scan.CrashSettings) []string {
	if s == nil {
		return []string{"Impostazioni dei dump non leggibili."}
	}
	what := "valore non indicato"
	if s.DumpEnabled != nil {
		if t, ok := dumpEnabledText[*s.DumpEnabled]; ok {
			what = t
		} else {
			what = "valore " + strconv.Itoa(*s.DumpEnabled)
		}
		if *s.DumpEnabled == 1 && s.FilterPages {
			what = "dump della memoria attiva"
		}
	}
	out := []string{"Salvataggio dopo una schermata blu: " + what}
	if s.MinidumpDir != "" {
		out = append(out, "Cartella dei minidump: "+s.MinidumpDir)
	}
	var flags []string
	if s.AutoReboot != nil {
		flags = append(flags, "riavvio automatico "+yesNo(*s.AutoReboot))
	}
	if s.LogEvent != nil {
		flags = append(flags, "evento nel registro di sistema "+yesNo(*s.LogEvent))
	}
	if s.Overwrite != nil {
		flags = append(flags, "sovrascrive MEMORY.DMP "+yesNo(*s.Overwrite))
	}
	if len(flags) > 0 {
		out = append(out, strings.ToUpper(flags[0][:1])+strings.Join(flags, ", ")[1:])
	}
	return out
}

func yesNo(b bool) string {
	if b {
		return "sì"
	}
	return "no"
}

func codeText(c scan.CrashDump) string {
	v, err := strconv.ParseUint(strings.TrimPrefix(c.Code, "0x"), 16, 32)
	if c.Code == "" || err != nil {
		return "codice non scritto nel file"
	}
	return crash.CodeText(uint32(v))
}

func printCrashes(d *scan.CrashData, loc *time.Location) {
	for _, l := range settingsText(d.Settings) {
		fmt.Println(l)
	}
	if d.Settings != nil && d.Settings.DumpEnabled != nil && *d.Settings.DumpEnabled == 0 {
		fmt.Println("  Windows non salva nulla dopo una schermata blu: le prossime non lasceranno file da esaminare.")
	}
	fmt.Println()
	switch {
	case d.Partial && d.Folder == "":
		fmt.Println("Lettura dei file delle schermate blu non finita in tempo.")
	case d.Folder == "denied":
		fmt.Println("Cartella dei minidump non leggibile.")
	case d.Folder == "error":
		fmt.Println("Cartella dei minidump non leggibile: errore di lettura.")
	case d.Folder == "missing" || d.Total == 0:
		fmt.Println("Nessun file di schermata blu nella cartella dei minidump.")
	case len(d.Dumps) == 0:
		fmt.Printf("Nella cartella dei minidump ci sono %d file, ma nessuno è stato letto.\n", d.Total)
	default:
		n := fmt.Sprintf("%d", d.Total)
		if d.Total > len(d.Dumps) {
			n = fmt.Sprintf("%d (mostrati i %d più recenti)", d.Total, len(d.Dumps))
		}
		fmt.Printf("Schermate blu nei minidump: %s\n", n)
	}
	for _, c := range d.Dumps {
		fmt.Println()
		printDump(c, loc)
	}
	if m := d.MemoryDump; m != nil {
		fmt.Println()
		fmt.Println("Dump della memoria (MEMORY.DMP):")
		printDump(*m, loc)
	}
	if d.Partial && d.Folder != "" {
		fmt.Println()
		fmt.Println("Lettura interrotta prima della fine: l'elenco è parziale.")
	}
	if d.NeedsAdmin {
		fmt.Println()
		fmt.Println("Per leggere i file delle schermate blu serve avviare Polaris come amministratore.")
	}
	if len(d.Dumps) > 0 {
		fmt.Println()
		fmt.Println("Il driver indicato è un indizio, non una certezza: Polaris non usa i simboli di debug e")
		fmt.Println("non ricostruisce lo stack completo. Per un'analisi certa serve WinDbg (!analyze -v).")
	}
}

func printDump(c scan.CrashDump, loc *time.Location) {
	when := "data non scritta nel file"
	if t, err := time.Parse(time.RFC3339, c.Time); err == nil {
		when = t.In(loc).Format("02/01/2006 15:04")
	} else if t, err := time.Parse(time.RFC3339, c.Modified); err == nil {
		when = t.In(loc).Format("02/01/2006 15:04") + " (data del file)"
	}
	if c.Error != "" {
		fmt.Printf("%s  %s\n", when, c.File)
		fmt.Printf("  Non letto: %s\n", c.Error)
		return
	}
	fmt.Printf("%s  %s\n", when, codeText(c))
	var ps []string
	for _, p := range c.Params {
		ps = append(ps, orDash(p))
	}
	if len(ps) > 0 {
		fmt.Printf("  Parametri: %s\n", strings.Join(ps, "  "))
	}
	if p := c.Probable; p != nil {
		how := "dallo stack salvato"
		if p.Method == "param" {
			how = fmt.Sprintf("dall'indirizzo nel parametro %d", p.Param)
		}
		extra := ""
		if p.Unloaded {
			extra = ", già scaricato al momento dell'arresto"
		}
		fmt.Printf("  Driver indicato (indizio, %s): %s +%s%s\n", how, p.Driver, strings.TrimPrefix(p.Offset, "0x"), extra)
	} else if t := noCulpritText(c); t != "" {
		fmt.Printf("  Driver indicato: %s\n", t)
	}
	var others []string
	for _, m := range c.Stack {
		if c.Probable == nil || !strings.EqualFold(m, c.Probable.Driver) {
			others = append(others, m)
		}
	}
	if len(others) > 0 {
		fmt.Printf("  Altri moduli nello stack: %s\n", strings.Join(others, ", "))
	}
	facts := []string{c.File, dumpTypeText[orUnknown(c.DumpType)], bytesText(c.Size)}
	if c.Build > 0 {
		facts = append(facts, fmt.Sprintf("build %d", c.Build))
	}
	if c.Machine != "" {
		facts = append(facts, c.Machine)
	}
	if t := limitedText[c.Limited]; t != "" {
		facts = append(facts, t)
	}
	fmt.Printf("  File: %s\n", strings.Join(facts, ", "))
}

// noCulpritText spiega perché un file letto non ha un driver indicato, come
// la scheda dell'interfaccia (noCulpritText in core/src/engine/crash.ts).
// Si saltano solo kernel, HAL e PSHED (crash.Ignored): gli altri driver di
// Windows possono essere indicati. "" se il motivo è già nella riga File.
func noCulpritText(c scan.CrashDump) string {
	v, err := strconv.ParseUint(strings.TrimPrefix(c.Code, "0x"), 16, 32)
	switch {
	case c.Code == "" || err != nil:
		return "non cercato, codice non scritto nel file"
	case crash.Manual(uint32(v)):
		return "nessuno, arresto provocato di proposito"
	case v == 0x124:
		return "nessuno, errore segnalato dall'hardware"
	case c.Limited != "" || c.DumpType != "triage":
		return ""
	}
	return "nessun driver fuori dal nucleo di Windows (kernel e HAL) nello stack salvato"
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
