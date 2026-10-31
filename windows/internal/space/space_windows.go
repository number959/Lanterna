//go:build windows

package space

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

const (
	fileListDirectory       = 0x0001
	fileIDBothDirectoryInfo = 10
	fileFullDirectoryInfo   = 14
	listBuffer              = 64 << 10
)

// classify traduce gli errori di Windows in quelli del pacchetto.
func classify(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return fmt.Errorf("%w: %v", errGone, err)
	case errors.Is(err, windows.ERROR_ACCESS_DENIED), errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD), errors.Is(err, windows.ERROR_SHARING_VIOLATION):
		return fmt.Errorf("%w: %v", errDenied, err)
	}
	return err
}

// winLister legge le cartelle con GetFileInformationByHandleEx: una sola
// chiamata restituisce decine o centinaia di voci, con dimensione, spazio
// occupato, attributi e numero del file.
type winLister struct {
	bufs sync.Pool
}

// longPath aggiunge il prefisso \\?\ per superare il limite di 260 caratteri.
func longPath(p string) string {
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	return `\\?\` + p
}

func (w *winLister) List(path string) ([]entry, error) {
	p, err := windows.UTF16PtrFromString(longPath(path))
	if err != nil {
		return nil, err
	}
	// Senza il privilegio di backup attivo i permessi delle cartelle valgono.
	h, err := windows.CreateFile(p, fileListDirectory, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, classify(err)
	}
	defer windows.CloseHandle(h)
	bp, _ := w.bufs.Get().(*[]byte)
	if bp == nil {
		b := make([]byte, listBuffer)
		bp = &b
	}
	defer w.bufs.Put(bp)
	buf := *bp
	var out []entry
	class, parse := uint32(fileIDBothDirectoryInfo), parseDirInfo
	for first := true; ; first = false {
		err := windows.GetFileInformationByHandleEx(h, class, &buf[0], uint32(len(buf)))
		// La radice di un'unità vuota non ha "." e "..": la prima lettura
		// risponde "file non trovato" (come gestisce anche os.ReadDir).
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) || first && errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return out, nil
		}
		// File system senza la classe con il numero del file: si riprova
		// con quella senza, sulla stessa cartella appena aperta.
		if first && class == fileIDBothDirectoryInfo && (errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_FUNCTION)) {
			class, parse, first = fileFullDirectoryInfo, parseFullDirInfo, true
			err = windows.GetFileInformationByHandleEx(h, class, &buf[0], uint32(len(buf)))
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) || errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				return out, nil
			}
		}
		if err != nil {
			return out, classify(err)
		}
		out = parse(buf, out)
	}
}

// Normalize controlla e normalizza il percorso da analizzare: "C:", "C:\" o
// una cartella di un'unità locale (dischi interni ed esterni). Niente
// percorsi di rete né di dispositivo.
func Normalize(root string) (string, error) {
	r := strings.ReplaceAll(strings.TrimSpace(root), "/", `\`)
	if len(r) == 2 && r[1] == ':' {
		r += `\`
	}
	if len(r) < 3 || r[1] != ':' || r[2] != '\\' || !(r[0] >= 'A' && r[0] <= 'Z' || r[0] >= 'a' && r[0] <= 'z') {
		return "", errors.New("indicare un'unità (per esempio C:) o una sua cartella")
	}
	r = filepath.Clean(r)
	if len(r) == 2 {
		r += `\`
	}
	r = strings.ToUpper(r[:1]) + r[1:]
	d, err := windows.UTF16PtrFromString(r[:3])
	if err != nil {
		return "", err
	}
	switch windows.GetDriveType(d) {
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE:
	default:
		return "", fmt.Errorf("%s non è un'unità locale: si analizzano solo i dischi del PC e quelli esterni", r[:2])
	}
	fi, err := os.Stat(r)
	if err != nil || !fi.IsDir() {
		return "", fmt.Errorf("cartella non trovata: %s", r)
	}
	return r, nil
}

func volumeOf(root string) Volume {
	v := Volume{Drive: root[:2]}
	d, err := windows.UTF16PtrFromString(root[:3])
	if err != nil {
		return v
	}
	var avail, total, free uint64
	if windows.GetDiskFreeSpaceEx(d, &avail, &total, &free) == nil {
		v.TotalBytes, v.FreeBytes = int64(total), int64(free)
	}
	fs := make([]uint16, 64)
	if windows.GetVolumeInformation(d, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))) == nil {
		v.FS = windows.UTF16ToString(fs)
	}
	return v
}

// long espande i nomi brevi 8.3 (MARIO~1) che possono comparire nelle
// variabili d'ambiente, così i percorsi si confrontano con quelli letti.
func long(p string) string {
	if p == "" {
		return ""
	}
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(u, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return strings.TrimSuffix(p, `\`)
	}
	return strings.TrimSuffix(windows.UTF16ToString(buf[:n]), `\`)
}

// currentEnv legge i percorsi del PC dalle variabili d'ambiente.
func currentEnv() Env {
	e := Env{
		SystemRoot:   long(os.Getenv("SystemRoot")),
		Temp:         long(os.Getenv("TEMP")),
		LocalAppData: long(os.Getenv("LOCALAPPDATA")),
		ProgramData:  long(os.Getenv("ProgramData")),
		UserProfile:  long(os.Getenv("USERPROFILE")),
		OneDrive:     long(os.Getenv("OneDrive")),
		Username:     os.Getenv("USERNAME"),
	}
	if e.UserProfile != "" {
		e.ProfilesDir = filepath.Dir(e.UserProfile)
		skip := map[string]bool{"public": true, "default": true, "default user": true, "all users": true, strings.ToLower(filepath.Base(e.UserProfile)): true}
		if ents, err := os.ReadDir(e.ProfilesDir); err == nil {
			for _, d := range ents {
				if d.IsDir() && !skip[strings.ToLower(d.Name())] {
					e.OtherProfiles = append(e.OtherProfiles, d.Name())
				}
			}
		}
	}
	return e
}

var exposeOnce sync.Once

// exposePlaceholders chiede a Windows di mostrare i file solo online di
// OneDrive per quello che sono (attributi di richiamo e reparse), invece di
// mascherarli da file normali: così si contano a parte. Disponibile da
// Windows 10 1803; un errore lascia il comportamento predefinito.
func exposePlaceholders() {
	exposeOnce.Do(func() {
		const phcmExposePlaceholders = 2
		p := windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlSetProcessPlaceholderCompatibilityMode")
		if p.Find() == nil {
			_, _, _ = p.Call(phcmExposePlaceholders)
		}
	})
}

// Scan analizza un'unità ("C:") o una sua cartella.
func Scan(ctx context.Context, root string, opt Options) (*Result, error) {
	r, err := Normalize(root)
	if err != nil {
		return nil, err
	}
	exposePlaceholders()
	return scanWith(ctx, &winLister{}, r, volumeOf(r), currentEnv(), opt)
}

// Open apre una cartella in Esplora file, o la cartella di un file con il
// file selezionato.
func Open(path string, selectFile bool) error {
	// Esplora file divide gli argomenti alle virgole e apre ciò che riceve:
	// un nome con le virgolette (possibile su una chiavetta preparata ad
	// arte) uscirebbe dalle virgolette. Su NTFS non ci sono nomi così.
	for _, r := range path {
		if r == '"' || r < 0x20 {
			return errors.New("percorso non valido")
		}
	}
	args := `"` + path + `"`
	if selectFile {
		args = `/select,"` + path + `"`
	}
	verb, _ := windows.UTF16PtrFromString("open")
	exe, _ := windows.UTF16PtrFromString("explorer.exe")
	a, err := windows.UTF16PtrFromString(args)
	if err != nil {
		return err
	}
	return windows.ShellExecute(0, verb, exe, a, nil, windows.SW_SHOWNORMAL)
}
