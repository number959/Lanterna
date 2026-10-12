//go:build windows

package gui

import (
	"os"
	"path/filepath"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"
	"github.com/jchv/go-webview2/webviewloader"
	"golang.org/x/sys/windows"
)

// RuntimeVersion restituisce la versione di WebView2 installata ("" se manca).
func RuntimeVersion() string {
	v, _ := webviewloader.GetInstalledVersion()
	return v
}

// Run apre la finestra sull'URL indicato e ritorna quando viene chiusa.
func Run(url string) error {
	// Si verifica il runtime prima di creare la finestra: senza, go-webview2
	// mostrerebbe comunque una finestra vuota. LANTERNA_SKIP_WEBVIEW2_CHECK=1
	// salta il controllo (solo per collaudare la gestione dell'errore).
	if os.Getenv("LANTERNA_SKIP_WEBVIEW2_CHECK") != "1" {
		if v, err := webviewloader.GetInstalledVersion(); err == nil && v == "" {
			return ErrNoWebView2
		}
	}
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
		hideOrphanWindow()
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

// hideOrphanWindow nasconde la finestra che go-webview2 crea e mostra prima
// di incorporare WebView2 e che lascia aperta se l'incorporamento fallisce.
// Non la si distrugge: la sua procedura, su WM_DESTROY, chiama
// PostQuitMessage e il WM_QUIT chiuderebbe subito il messaggio di avviso.
// Resta nascosta fino all'uscita del programma.
func hideOrphanWindow() {
	user32 := windows.NewLazySystemDLL("user32.dll")
	find, show := user32.NewProc("FindWindowW"), user32.NewProc("ShowWindow")
	cls, _ := windows.UTF16PtrFromString("webview")
	h, _, _ := find.Call(uintptr(unsafe.Pointer(cls)), 0)
	if h == 0 {
		return
	}
	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(windows.HWND(h), &pid); err == nil && pid == windows.GetCurrentProcessId() {
		show.Call(h, 0) // SW_HIDE
	}
}
