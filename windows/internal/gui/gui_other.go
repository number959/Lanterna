//go:build !windows

package gui

import "fmt"

func Run(string) error       { return ErrNoWebView2 }
func Fallback(url string)    { fmt.Println("Apri nel browser:", url) }
func Error(msg string)       { fmt.Println(msg) }
func RuntimeVersion() string { return "" }
