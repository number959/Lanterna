//go:build !windows

package bench

import (
	"os"

	"golang.org/x/sys/unix"
)

// Fuori da Windows il test serve solo alle prove automatiche: file normale,
// con la cache del sistema (i valori non sono indicativi).
type tempFile struct{ *os.File }

func (f tempFile) Close() error {
	err := f.File.Close()
	_ = os.Remove(f.Name())
	return err
}

func createFile(dir string) (file, error) {
	f, err := os.CreateTemp(dir, "polaris-test-*.tmp")
	if err != nil {
		return nil, err
	}
	return tempFile{f}, nil
}

func freeBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// DirFor usa la cartella temporanea: le lettere di unità esistono solo su
// Windows.
func DirFor(drive string) (string, error) {
	if _, err := NormalizeDrive(drive); err != nil {
		return "", err
	}
	return os.TempDir(), nil
}
