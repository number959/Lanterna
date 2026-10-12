// Package gui apre la finestra nativa che ospita l'interfaccia.
package gui

import "errors"

// ErrNoWebView2 indica che il runtime Microsoft Edge WebView2 non è presente.
var ErrNoWebView2 = errors.New("runtime WebView2 non disponibile")
