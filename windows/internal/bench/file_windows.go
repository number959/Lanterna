//go:build windows

package bench

import (
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// winFile è aperto con FILE_FLAG_OVERLAPPED: ogni esecutore ha la sua
// struttura OVERLAPPED e il suo evento, così più goroutine tengono in corso
// operazioni contemporanee sullo stesso handle (con un handle sincrono
// Windows le eseguirebbe una alla volta).
type winFile struct{ h windows.Handle }

func (f winFile) worker() (rw, error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	// new alloca sullo heap: la struttura non si sposta mentre il sistema la usa.
	return &winWorker{h: f.h, ev: ev, ov: new(windows.Overlapped)}, nil
}

func (f winFile) Sync() error  { return windows.FlushFileBuffers(f.h) }
func (f winFile) Close() error { return windows.CloseHandle(f.h) }

type winWorker struct {
	h, ev windows.Handle
	ov    *windows.Overlapped
}

// do avvia l'operazione dall'offset indicato e ne attende la fine: se il
// sistema la completa subito GetOverlappedResult ritorna immediatamente.
func (w *winWorker) do(p []byte, off int64, write bool) (int, error) {
	*w.ov = windows.Overlapped{Offset: uint32(off), OffsetHigh: uint32(off >> 32), HEvent: w.ev}
	var n uint32
	var err error
	if write {
		err = windows.WriteFile(w.h, p, &n, w.ov)
	} else {
		err = windows.ReadFile(w.h, p, &n, w.ov)
	}
	if err != nil && err != windows.ERROR_IO_PENDING {
		return 0, err
	}
	if err := windows.GetOverlappedResult(w.h, w.ov, &n, true); err != nil {
		return int(n), err
	}
	if int(n) < len(p) {
		if write {
			return int(n), io.ErrShortWrite
		}
		return int(n), io.ErrUnexpectedEOF
	}
	return int(n), nil
}

func (w *winWorker) ReadAt(p []byte, off int64) (int, error)  { return w.do(p, off, false) }
func (w *winWorker) WriteAt(p []byte, off int64) (int, error) { return w.do(p, off, true) }
func (w *winWorker) Close() error                             { return windows.CloseHandle(w.ev) }

// createFile crea il file di prova: senza cache di sistema, temporaneo,
// cancellato da Windows alla chiusura dell'handle (anche in caso di crash) e
// con I/O sovrapposto per le misure con più richieste in coda.
func createFile(dir string) (file, error) {
	name := filepath.Join(dir, fmt.Sprintf("polaris-test-%d-%08x.tmp", os.Getpid(), rand.Uint32()))
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_TEMPORARY|windows.FILE_FLAG_NO_BUFFERING|windows.FILE_FLAG_DELETE_ON_CLOSE|windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, err
	}
	return winFile{h}, nil
}

func freeBytes(dir string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, err
	}
	return free, nil
}

// DirFor sceglie dove creare il file di prova sull'unità indicata: la
// cartella temporanea dell'utente se sta su quell'unità, altrimenti la
// radice. Solo dischi locali e rimovibili: niente unità di rete o CD.
func DirFor(drive string) (string, error) {
	d, err := NormalizeDrive(drive)
	if err != nil {
		return "", err
	}
	root, _ := windows.UTF16PtrFromString(d + `\`)
	switch windows.GetDriveType(root) {
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE:
	default:
		return "", fmt.Errorf("%s non è un disco locale o rimovibile", d)
	}
	if tmp := os.TempDir(); strings.EqualFold(filepath.VolumeName(tmp), d) {
		return tmp, nil
	}
	return d + `\`, nil
}
