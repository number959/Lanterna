//go:build windows

package gui

import (
	"os"
	"path/filepath"

	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
)

// Run apre la finestra sull'URL indicato e ritorna quando viene chiusa.
func Run(url string) error {
	// Dati del motore WebView2 fuori dalla cartella del programma, che deve
	// restare portatile (anche su chiavetta in sola lettura).
	data := filepath.Join(os.Getenv("LOCALAPPDATA"), "LANterna", "WebView2")
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		DataPath:  data,
		WindowOptions: webview2.WindowOptions{
			Title:  "LANterna",
			Width:  1320,
			Height: 880,
			IconId: 1, // icona incorporata da go-winres (rsrc_windows_*.syso)
			Center: true,
		},
	})
	if w == nil {
		return ErrNoWebView2
	}
	defer w.Destroy()
	w.Navigate(url)
	w.Run()
	return nil
}

// Fallback avvisa che manca WebView2, apre l'interfaccia nel browser
// predefinito e tiene vivo il programma finché l'utente non lo chiude.
func Fallback(url string) {
	open(url)
	msg := "Su questo PC manca il componente Microsoft Edge WebView2, quindi LANterna si è aperto nel browser:\n\n" + url +
		"\n\nPer la finestra integrata installa \"WebView2 Runtime\" dal sito Microsoft (gratuito).\n\nPremi OK per chiudere LANterna."
	t, _ := windows.UTF16PtrFromString("LANterna")
	m, _ := windows.UTF16PtrFromString(msg)
	windows.MessageBox(0, m, t, windows.MB_OK|windows.MB_ICONINFORMATION|windows.MB_SETFOREGROUND)
}

func open(url string) {
	verb, _ := windows.UTF16PtrFromString("open")
	u, _ := windows.UTF16PtrFromString(url)
	_ = windows.ShellExecute(0, verb, u, nil, nil, windows.SW_SHOWNORMAL)
}

// Error mostra un errore bloccante in una finestra di dialogo.
func Error(msg string) {
	t, _ := windows.UTF16PtrFromString("LANterna")
	m, _ := windows.UTF16PtrFromString(msg)
	windows.MessageBox(0, m, t, windows.MB_OK|windows.MB_ICONERROR)
}
