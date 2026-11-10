//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

func attachConsole() {}

// readSecret legge una riga dallo standard input. Fuori da Windows il testo
// resta visibile: il programma completo gira solo su Windows.
func readSecret(prompt string, _ io.Reader, br *bufio.Reader) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	return readLine(br)
}
