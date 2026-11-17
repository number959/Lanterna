package pcinfo

import (
	"encoding/binary"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"

	"lanterna/internal/scan"
)

// Schermi collegati, per la scheda tecnica e il requisito di Windows 11
// sullo schermo (720p, almeno 9 pollici, 8 bit per canale). Due fonti:
//   - QueryDisplayConfig e DisplayConfigGetDeviceInfo (user32, lettura
//     nativa in display_windows.go): percorsi attivi, risoluzione del
//     desktop, tipo di collegamento, bit per canale;
//   - WmiMonitorBasicDisplayParams e WmiMonitorConnectionParams (root\wmi,
//     nello script PowerShell): dimensioni dichiarate in cm.
//
// L'EDID non si legge dal registro (posizione non documentata, contiene il
// numero di serie dello schermo). Il nome dello schermo e il percorso del
// dispositivo (con l'ID d'istanza) servono solo ad abbinare le due fonti:
// non escono dal processo.

// Strutture di wingdi.h (mingw-w64, di pubblico dominio; scostamenti
// controllati con clang per x86_64, aarch64 e i686, MSVC e mingw):
// DISPLAYCONFIG_PATH_INFO 72 byte (sourceInfo.modeInfoIdx a 12;
// targetInfo.adapterId a 20, id a 28, outputTechnology a 36),
// DISPLAYCONFIG_MODE_INFO 64 byte (infoType a 0, sourceMode.width a 16,
// height a 20), DISPLAYCONFIG_DEVICE_INFO_HEADER 20 byte (type, size,
// adapterId a 8, id a 16), DISPLAYCONFIG_TARGET_DEVICE_NAME 420 byte
// (outputTechnology a 24, monitorDevicePath[128] a 164),
// DISPLAYCONFIG_GET_ADVANCED_COLOR_INFO 32 byte (bitsPerColorChannel a 28).
const (
	dcPathSize        = 72
	dcModeSize        = 64
	dcHeaderSize      = 20
	dcTargetNameSize  = 420
	dcAdvColorSize    = 32
	dcModeTypeSource  = 1
	dcModeIdxInvalid  = 0xFFFFFFFF
	dcInfoTargetName  = 2 // DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME
	dcInfoAdvColor    = 9 // DISPLAYCONFIG_DEVICE_INFO_GET_ADVANCED_COLOR_INFO
	dcTargetPathAt    = 164
	dcTargetPathChars = 128
	dcTargetTechAt    = 24
	dcAdvColorBitsAt  = 28
	maxDisplays       = 8
)

// Valori di DISPLAYCONFIG_VIDEO_OUTPUT_TECHNOLOGY (gli stessi di
// D3DKMDT_VIDEO_OUTPUT_TECHNOLOGY, che usa WmiMonitorConnectionParams) che
// indicano uno schermo integrato: INTERNAL e i collegamenti «embedded».
const (
	techDisplayPortEmbedded = 11
	techUDIEmbedded         = 13
	techInternal            = 0x80000000
)

// rawDisplay è un percorso attivo come lo legge l'agente.
type rawDisplay struct {
	AdapterLow  uint32
	AdapterHigh uint32
	TargetID    uint32
	Tech        uint32
	HasTech     bool
	Width       int
	Height      int
	Bits        int
	// Path è monitorDevicePath ("\\?\DISPLAY#DELA0B2#5&...#{e6f07b5f-...}"):
	// solo per l'abbinamento, non esce dal processo.
	Path string
}

// psMonitor rispecchia la sezione "mon" dello script: dimensioni in cm e
// tipo di collegamento. ID è InstanceName ("DISPLAY\DELA0B2\5&..._0"): solo
// per l'abbinamento, non esce dal processo.
type psMonitor struct {
	ID  string `json:"id"`
	W   int    `json:"w"`
	H   int    `json:"h"`
	Vot *int64 `json:"vot"`
}

// parseDisplayConfig legge i percorsi restituiti da QueryDisplayConfig:
// adattatore e uscita di destinazione, tipo di collegamento e risoluzione
// del desktop dalla modalità della sorgente.
func parseDisplayConfig(paths []byte, np int, modes []byte, nm int) []rawDisplay {
	le := binary.LittleEndian
	var out []rawDisplay
	for i := 0; i < np && (i+1)*dcPathSize <= len(paths); i++ {
		p := paths[i*dcPathSize : (i+1)*dcPathSize]
		d := rawDisplay{
			AdapterLow:  le.Uint32(p[20:]),
			AdapterHigh: le.Uint32(p[24:]),
			TargetID:    le.Uint32(p[28:]),
			Tech:        le.Uint32(p[36:]),
			HasTech:     true,
		}
		if idx := le.Uint32(p[12:]); idx != dcModeIdxInvalid && int(idx) < nm && (int(idx)+1)*dcModeSize <= len(modes) {
			m := modes[int(idx)*dcModeSize:]
			if le.Uint32(m) == dcModeTypeSource {
				w, h := le.Uint32(m[16:]), le.Uint32(m[20:])
				if w > 0 && h > 0 && w <= 32768 && h <= 32768 {
					d.Width, d.Height = int(w), int(h)
				}
			}
		}
		out = append(out, d)
	}
	return out
}

// dcHeader prepara l'intestazione DISPLAYCONFIG_DEVICE_INFO_HEADER di una
// richiesta a DisplayConfigGetDeviceInfo nel buffer b.
func dcHeader(b []byte, typ, size uint32, d rawDisplay) {
	if len(b) < dcHeaderSize {
		return
	}
	le := binary.LittleEndian
	le.PutUint32(b[0:], typ)
	le.PutUint32(b[4:], size)
	le.PutUint32(b[8:], d.AdapterLow)
	le.PutUint32(b[12:], d.AdapterHigh)
	le.PutUint32(b[16:], d.TargetID)
}

// parseTargetName legge da DISPLAYCONFIG_TARGET_DEVICE_NAME il tipo di
// collegamento e il percorso del dispositivo dello schermo.
func parseTargetName(b []byte) (path string, tech uint32, ok bool) {
	if len(b) < dcTargetNameSize {
		return "", 0, false
	}
	tech = binary.LittleEndian.Uint32(b[dcTargetTechAt:])
	return utf16At(b[dcTargetPathAt:], dcTargetPathChars), tech, true
}

// parseAdvancedColor legge i bit per canale; 0 se il valore non è plausibile.
func parseAdvancedColor(b []byte) int {
	if len(b) < dcAdvColorSize {
		return 0
	}
	v := binary.LittleEndian.Uint32(b[dcAdvColorBitsAt:])
	if v < 5 || v > 16 {
		return 0
	}
	return int(v)
}

// utf16At legge una stringa UTF-16 di al massimo n caratteri, fino al primo NUL.
func utf16At(b []byte, n int) string {
	u := make([]uint16, 0, n)
	for i := 0; i < n && 2*i+1 < len(b); i++ {
		c := binary.LittleEndian.Uint16(b[2*i:])
		if c == 0 {
			break
		}
		u = append(u, c)
	}
	return string(utf16.Decode(u))
}

// internalTech dice se il collegamento è quello di uno schermo integrato.
func internalTech(v uint32) bool {
	return v == techInternal || v == techDisplayPortEmbedded || v == techUDIEmbedded
}

var instanceSuffix = regexp.MustCompile(`_\d+$`)

// monitorKey riduce il percorso del dispositivo di uno schermo
// ("\\?\DISPLAY#DELA0B2#5&2a0c4b4&0&UID4353#{e6f07b5f-...}") e il nome
// dell'istanza WMI ("DISPLAY\DELA0B2\5&2a0c4b4&0&UID4353_0") alla stessa
// forma, per abbinare le due fonti.
func monitorKey(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if strings.HasPrefix(s, `\\?\`) {
		s = s[4:]
		if i := strings.Index(s, "#{"); i >= 0 {
			s = s[:i]
		}
		s = strings.ReplaceAll(s, "#", `\`)
		return s
	}
	return instanceSuffix.ReplaceAllString(s, "")
}

// diagonalIn calcola la diagonale in pollici, con una cifra decimale, dalle
// dimensioni in cm dichiarate dallo schermo. Microsoft: se una delle due è
// zero non si può dedurre nulla sulle dimensioni; anche i valori fuori da
// ogni schermo reale (meno di 4 o più di 400 pollici) valgono «sconosciuta».
func diagonalIn(wcm, hcm int) float64 {
	if wcm <= 0 || hcm <= 0 {
		return 0
	}
	d := math.Sqrt(float64(wcm*wcm+hcm*hcm)) / 2.54
	if d < 4 || d > 400 {
		return 0
	}
	return math.Round(d*10) / 10
}

// BuildDisplays unisce le due fonti: per ogni percorso attivo la
// risoluzione, i bit per canale e il tipo di collegamento; dalla lettura WMI
// dello stesso schermo la diagonale. Senza lettura nativa (sessione senza
// desktop, Windows che non risponde) restano gli schermi WMI, e la
// risoluzione solo se c'è un solo schermo e una sola scheda video che la
// riporta. Gli schermi integrati vengono prima.
func BuildDisplays(native []rawDisplay, wmi []psMonitor, gpus []scan.PcGPU) []scan.Display {
	byKey := map[string]psMonitor{}
	for _, m := range wmi {
		if k := monitorKey(m.ID); k != "" {
			byKey[k] = m
		}
	}
	var out []scan.Display
	if len(native) > 0 {
		for _, n := range native {
			d := scan.Display{Width: n.Width, Height: n.Height, BitsPerColor: n.Bits}
			if n.HasTech {
				d.Internal = internalTech(n.Tech)
			}
			if m, ok := byKey[monitorKey(n.Path)]; ok && n.Path != "" {
				d.DiagonalIn = diagonalIn(m.W, m.H)
				if !n.HasTech && m.Vot != nil {
					d.Internal = internalTech(uint32(*m.Vot))
				}
			}
			out = append(out, d)
		}
	} else {
		for _, m := range wmi {
			d := scan.Display{DiagonalIn: diagonalIn(m.W, m.H)}
			if m.Vot != nil {
				d.Internal = internalTech(uint32(*m.Vot))
			}
			out = append(out, d)
		}
		if len(out) == 1 {
			var withRes []scan.PcGPU
			for _, g := range gpus {
				if g.Width > 0 && g.Height > 0 {
					withRes = append(withRes, g)
				}
			}
			if len(withRes) == 1 {
				out[0].Width, out[0].Height = withRes[0].Width, withRes[0].Height
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Internal && !out[j].Internal })
	if len(out) > maxDisplays {
		out = out[:maxDisplays]
	}
	return out
}
