//go:build !windows

package main

import (
	"fmt"
	"io"
	"os"
)

func attachConsole() {}

// readSecret legge una riga dallo standard input. Fuori da Windows il testo
// resta visibile: il programma completo gira solo su Windows.
func readSecret(prompt string, in io.Reader) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	return readLine(in)
}
