package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// Bundle è un programma incluso nel pacchetto di Polaris: la copia originale
// del produttore, estratta senza modifiche in strumenti/<Dir> accanto
// all'eseguibile (scripts/strumenti.sh, che verifica l'archivio scaricato).
type Bundle struct {
	Dir     string
	Version string
	// Exe è l'eseguibile per architettura (GOARCH) con la sua impronta
	// SHA-256: Polaris avvia solo il file originale, non uno modificato o
	// sostituito.
	Exe map[string]Binary
}

// Binary è un eseguibile con la sua impronta SHA-256.
type Binary struct {
	Name, SHA256 string
}

// Bundled sono i programmi inclusi. Gli archivi originali e le loro impronte
// sono in scripts/strumenti.sh; qui ci sono le impronte degli eseguibili che
// contengono, firmati dal produttore (CrystalMark Inc., Nir Sofer).
// BlueScreenView esiste solo a 32 e 64 bit: su Windows per ARM gira emulato.
var Bundled = map[string]Bundle{
	"crystaldiskinfo": {Dir: "CrystalDiskInfo", Version: "9.9.2", Exe: map[string]Binary{
		"amd64": {"DiskInfo64.exe", "3be01fbd2189c2f8e70fcb97315f9d46baf7dfa8aa48a0dff0e399b787bd9ec3"},
		"arm64": {"DiskInfoA64.exe", "f1d722ae0f3c1718cefd58eb331e5eaa7056ef28913970f7c20dde187c6ec21c"},
		"386":   {"DiskInfo32.exe", "beed4e9fb91a06d5f20b50cdd942c91c89d3c550124bd2a8d0af13142a6cb255"},
	}},
	"crystaldiskmark": {Dir: "CrystalDiskMark", Version: "9.0.3", Exe: map[string]Binary{
		"amd64": {"DiskMark64.exe", "4ac51fcd01866696b41d2894227557941b272ffa2d685837a22862eb61fa0f33"},
		"arm64": {"DiskMarkA64.exe", "29ff72da6f5c0bb1a8a70583aabbaecf4c9eb836f304744ff77e3fd93849ba1c"},
		"386":   {"DiskMark32.exe", "c3b51e98143b0327cea9359b06165d12bcc1c5ad37664d43f0a384e9ff1ddf89"},
	}},
	"bluescreenview": {Dir: "BlueScreenView", Version: "1.55", Exe: map[string]Binary{
		"amd64": {"BlueScreenView.exe", "09f3023554be864f31d80f2e7e7c7e824d79a69ddf84f1f02a433e85e866282c"},
		"arm64": {"BlueScreenView.exe", "09f3023554be864f31d80f2e7e7c7e824d79a69ddf84f1f02a433e85e866282c"},
	}},
}

// Included è un programma incluso trovato accanto a Polaris. Se il file c'è
// ma non è l'originale, Problem lo spiega e Path resta vuoto: non si avvia.
type Included struct {
	Version string `json:"version"`
	Problem string `json:"problem,omitempty"`
	Path    string `json:"-"` // non esce dal PC: serve solo ad avviarlo
}

// FindBundled cerca sotto root (la cartella strumenti) i programmi inclusi
// per l'architettura arch e ne controlla l'impronta.
func FindBundled(root, arch string) map[string]Included {
	out := map[string]Included{}
	for id, b := range Bundled {
		bin, ok := b.Exe[arch]
		if !ok {
			continue
		}
		path := filepath.Join(root, b.Dir, bin.Name)
		sum, err := fileSHA256(path)
		if err != nil {
			continue // pacchetto senza programmi inclusi, o file rimosso
		}
		if sum != bin.SHA256 {
			out[id] = Included{Version: b.Version, Problem: "il file è stato modificato o sostituito: per sicurezza Polaris non lo avvia"}
			continue
		}
		out[id] = Included{Version: b.Version, Path: path}
	}
	return out
}

// BundledPrograms cerca i programmi inclusi nella cartella strumenti accanto
// all'eseguibile di Polaris.
func BundledPrograms() map[string]Included {
	exe, err := os.Executable()
	if err != nil {
		return map[string]Included{}
	}
	return FindBundled(filepath.Join(filepath.Dir(exe), "strumenti"), runtime.GOARCH)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
