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

// winFile esegue letture e scritture posizionate direttamente sull'handle:
// con un handle sincrono e la struttura OVERLAPPED l'operazione parte
// dall'offset indicato e termina prima del ritorno, senza chiamate extra.
type winFile struct{ h windows.Handle }

func (f winFile) ReadAt(p []byte, off int64) (int, error) {
	var n uint32
	o := windows.Overlapped{Offset: uint32(off), OffsetHigh: uint32(off >> 32)}
	err := windows.ReadFile(f.h, p, &n, &o)
	if err == nil && int(n) < len(p) {
		err = io.ErrUnexpectedEOF
	}
	return int(n), err
}

func (f winFile) WriteAt(p []byte, off int64) (int, error) {
	var n uint32
	o := windows.Overlapped{Offset: uint32(off), OffsetHigh: uint32(off >> 32)}
	err := windows.WriteFile(f.h, p, &n, &o)
	if err == nil && int(n) < len(p) {
		err = io.ErrShortWrite
	}
	return int(n), err
}

func (f winFile) Sync() error  { return windows.FlushFileBuffers(f.h) }
func (f winFile) Close() error { return windows.CloseHandle(f.h) }

// createFile crea il file di prova: senza cache di sistema, temporaneo e
// cancellato da Windows alla chiusura dell'handle (anche in caso di crash).
func createFile(dir string) (file, error) {
	name := filepath.Join(dir, fmt.Sprintf("polaris-test-%d-%08x.tmp", os.Getpid(), rand.Uint32()))
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_TEMPORARY|windows.FILE_FLAG_NO_BUFFERING|windows.FILE_FLAG_DELETE_ON_CLOSE, 0)
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
