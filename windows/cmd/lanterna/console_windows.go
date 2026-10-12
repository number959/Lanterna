//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// attachConsole serve alla versione grafica (subsystem "windows"): lanciata
// da un prompt con un comando come "report", si aggancia alla console del
// prompt per scriverci. Se l'output è rediretto su file o pipe non serve.
func attachConsole() {
	if h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); err == nil && h != 0 && h != windows.InvalidHandle {
		return
	}
	k := windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")
	if r, _, _ := k.Call(uintptr(^uint32(0))); r == 0 { // ATTACH_PARENT_PROCESS
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
	}
}
