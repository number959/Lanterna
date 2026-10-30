package space

// HintLabels sono i nomi in italiano delle cartelle e dei file noti, per la
// riga di comando; l'interfaccia ha in più spiegazioni e consigli.
var HintLabels = map[string]string{
	"temp-user":             "File temporanei dell'utente",
	"temp-windows":          "File temporanei di Windows",
	"update-cache":          "Download di Windows Update",
	"delivery-optimization": "Cache di Ottimizzazione recapito",
	"windows-old":           "Installazione precedente di Windows (Windows.old)",
	"upgrade-files":         "File dell'aggiornamento di Windows",
	"recycle-bin":           "Cestino",
	"winsxs":                "Archivio dei componenti di Windows (WinSxS)",
	"installer":             "Cache di Windows Installer",
	"error-reports":         "Segnalazioni degli errori",
	"crash-dumps":           "File di dump degli arresti anomali",
	"browser-cache":         "Cache dei browser",
	"package-cache":         "Cache dei pacchetti di installazione",
	"downloads":             "Cartella Download",
	"onedrive":              "OneDrive",
	"hibernation":           "File di ibernazione (hiberfil.sys)",
	"pagefile":              "File di paging",
	"virtual-disks":         "Dischi virtuali (WSL, Docker, macchine virtuali)",
}

// CategoryLabels sono i nomi in italiano delle categorie di file.
var CategoryLabels = map[string]string{
	"video":       "Video",
	"image":       "Immagini",
	"audio":       "Audio",
	"document":    "Documenti",
	"archive":     "Archivi e immagini disco",
	"program":     "Programmi e librerie",
	"virtualdisk": "Dischi virtuali",
	"system":      "File di sistema",
	"other":       "Altro",
}
