package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"lanterna/internal/l2disc"
	"lanterna/internal/netdisc"
	"lanterna/internal/snmp"
	"lanterna/internal/winapi"
)

// runDiscover scopre le altre reti e le VLAN, solo su richiesta:
//
//	discover routes            reti private note al PC (tabella di instradamento)
//	discover l2 [--secondi N]  annunci degli switch sulla porta del PC
//	discover ad                sottoreti definite in Active Directory
//	discover snmp IP           lettura SNMP in sola lettura di uno switch o router
func runDiscover(args []string) error {
	if len(args) == 0 {
		return errors.New("specificare routes, l2, ad oppure snmp (polaris-cli discover l2)")
	}
	kind, args := args[0], args[1:]
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	secs := fs.Int("secondi", int(l2disc.DefaultDuration/time.Second), "")
	v3 := fs.Bool("v3", false, "")
	auth := fs.String("auth", "", "")
	priv := fs.String("priv", "", "")
	authorized := fs.Bool("autorizzato", false, "")
	fs.Usage = func() { fmt.Fprintf(os.Stderr, usage, version) }
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return err
		}
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	show := func(v any, text func()) error {
		if *asJSON {
			b, _ := json.MarshalIndent(v, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		text()
		return nil
	}
	switch kind {
	case "routes":
		rs, err := netdisc.Routes()
		if err != nil {
			return err
		}
		return show(rs, func() { printRoutes(rs) })
	case "l2":
		if *secs < 10 || *secs > 180 {
			return errors.New("--secondi deve essere tra 10 e 180")
		}
		fmt.Fprintf(os.Stderr, "Ascolto degli annunci dello switch per %d secondi: Polaris non trasmette nulla (Ctrl+C per interrompere)...\n", *secs)
		d := l2disc.Listen(ctx, time.Duration(*secs)*time.Second)
		return show(d, func() { printL2(d) })
	case "ad":
		res := netdisc.ADSubnetsOf(ctx, winapi.Domain())
		return show(res, func() { printAD(res) })
	case "snmp":
		if len(pos) != 1 {
			return errors.New("indicare un solo indirizzo, per esempio: polaris-cli discover snmp 192.168.1.2 --autorizzato")
		}
		if !*authorized {
			return errors.New("aggiungi --autorizzato per confermare di essere autorizzato a interrogare questo dispositivo")
		}
		// L'indirizzo si controlla prima di chiedere le credenziali.
		if err := snmp.CheckTarget(pos[0]); err != nil {
			return err
		}
		cr, err := snmpCreds(*v3, *auth, *priv, os.Stdin)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Lettura SNMP in sola lettura di %s (%s), con ritmo prudente...\n", pos[0], cr)
		res, err := snmp.Collect(ctx, pos[0], cr, snmp.Prudent, func(step string) {
			fmt.Fprintf(os.Stderr, "  - %s\n", step)
		})
		if res == nil {
			return err
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "Lettura interrotta:", err)
		}
		return show(res, func() { printSNMP(res) })
	}
	return fmt.Errorf("scoperta sconosciuta: %s (routes, l2, ad oppure snmp)", kind)
}

// snmpCreds legge le credenziali: prima dalle variabili d'ambiente
// POLARIS_SNMP_COMMUNITY, POLARIS_SNMP_USER, POLARIS_SNMP_AUTH_PASS e
// POLARIS_SNMP_PRIV_PASS, altrimenti chiedendole senza mostrarle. Non si
// passano come argomenti: resterebbero nella cronologia del prompt e
// nell'elenco dei processi.
func snmpCreds(v3 bool, auth, priv string, in io.Reader) (snmp.Creds, error) {
	// Un solo lettore per tutte le domande: con le credenziali passate da una
	// pipe, un lettore nuovo per domanda perderebbe le righe già lette.
	br := bufio.NewReader(in)
	ask := func(env, prompt string) (string, error) {
		if v := os.Getenv(env); v != "" {
			return v, nil
		}
		return readSecret(prompt, in, br)
	}
	if !v3 {
		if auth != "" || priv != "" {
			return snmp.Creds{}, errors.New("--auth e --priv valgono solo con --v3")
		}
		c, err := ask("POLARIS_SNMP_COMMUNITY", "Community SNMPv2c (non verrà mostrata): ")
		return snmp.Creds{Version: "2c", Community: c}, err
	}
	cr := snmp.Creds{Version: "3", Auth: strings.ToUpper(auth), Priv: strings.ToUpper(priv)}
	var err error
	if cr.User, err = ask("POLARIS_SNMP_USER", "Utente SNMPv3 (non verrà mostrato): "); err != nil {
		return cr, err
	}
	if cr.Auth != "" {
		if cr.AuthPass, err = ask("POLARIS_SNMP_AUTH_PASS", "Password di autenticazione (non verrà mostrata): "); err != nil {
			return cr, err
		}
	}
	if cr.Priv != "" {
		if cr.PrivPass, err = ask("POLARIS_SNMP_PRIV_PASS", "Password di cifratura (non verrà mostrata): "); err != nil {
			return cr, err
		}
	}
	return cr, nil
}

// readLine legge una riga senza il ritorno a capo.
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", errors.New("credenziali non lette")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func printRoutes(rs []netdisc.Route) {
	if len(rs) == 0 {
		fmt.Println("La tabella di instradamento non indica altre reti private oltre a quella del PC.")
		return
	}
	fmt.Println("Altre reti private note al PC (tabella di instradamento):")
	for _, r := range rs {
		via := "collegata direttamente"
		if r.NextHop != "" {
			via = "attraverso " + r.NextHop
		}
		fmt.Printf("  %-20s %s (%s)\n", r.Prefix, via, r.Origin)
	}
}

var l2Read = map[string]string{
	l2disc.ReadNone:        "nessun annuncio ricevuto: lo switch non ha LLDP o CDP attivi verso il PC, oppure il PC è collegato a uno switch non gestito",
	l2disc.ReadNoWired:     "nessuna scheda cablata collegata: l'ascolto funziona solo con il cavo",
	l2disc.ReadAdmin:       "serve il Prompt dei comandi avviato come amministratore",
	l2disc.ReadUnsupported: "cattura dei pacchetti non disponibile su questo sistema",
}

func printL2(d l2disc.Discovery) {
	if d.Read != l2disc.ReadOK {
		msg := l2Read[d.Read]
		if d.Error != "" {
			msg = d.Error
		}
		fmt.Println("Annunci dello switch:", msg)
		return
	}
	fmt.Printf("Annunci ricevuti in %d secondi: %d trame (LLDP %d, CDP %d, DTP %d, Spanning Tree %d).\n", d.Seconds, d.Frames, d.Counts.Lldp, d.Counts.Cdp, d.Counts.Dtp, d.Counts.Stp)
	for _, n := range d.Lldp {
		name := n.SystemName
		if name == "" {
			name = n.ChassisID
		}
		fmt.Printf("\nSwitch (LLDP): %s, porta %s\n", name, orDash(n.PortID))
		if n.PortVlanID > 0 {
			fmt.Printf("  VLAN della porta (non etichettata): %d\n", n.PortVlanID)
		}
		if n.VoiceVlan > 0 {
			fmt.Printf("  VLAN della voce: %d\n", n.VoiceVlan)
		}
		for _, v := range n.Vlans {
			fmt.Printf("  VLAN annunciata: %d %s\n", v.ID, v.Name)
		}
		if len(n.ManagementAddresses) > 0 {
			fmt.Printf("  Indirizzo di gestione: %s\n", strings.Join(n.ManagementAddresses, ", "))
		}
		if n.SystemDescription != "" {
			fmt.Printf("  Modello: %s\n", n.SystemDescription)
		}
	}
	for _, n := range d.Cdp {
		fmt.Printf("\nSwitch (CDP): %s, porta %s\n", orDash(n.DeviceID), orDash(n.PortID))
		if n.NativeVlan > 0 {
			fmt.Printf("  VLAN nativa: %d\n", n.NativeVlan)
		}
		if n.VoiceVlan > 0 {
			fmt.Printf("  VLAN della voce: %d\n", n.VoiceVlan)
		}
		if n.Platform != "" {
			fmt.Printf("  Piattaforma: %s\n", n.Platform)
		}
	}
	for _, t := range d.Dtp {
		fmt.Printf("\nDTP attivo sulla porta (stato %s, modalità %s): la porta potrebbe negoziare un trunk con un dispositivo che lo chiede.\n", orDash(t.OperStatus), orDash(t.AdminStatus))
	}
	vlans := map[int]bool{}
	for _, s := range d.Stp {
		if s.Vlan > 0 {
			vlans[s.Vlan] = true
		}
	}
	if len(vlans) > 0 {
		list := make([]string, 0, len(vlans))
		for v := 1; v <= 4094 && len(list) < len(vlans); v++ {
			if vlans[v] {
				list = append(list, strconv.Itoa(v))
			}
		}
		fmt.Printf("\nVLAN viste negli annunci dello Spanning Tree (PVST+): %s\n", strings.Join(list, ", "))
	}
}

func printAD(r netdisc.ADSubnets) {
	switch r.Read {
	case "nodomain":
		fmt.Println("Il PC non fa parte di un dominio Active Directory: nessuna sottorete da leggere.")
		return
	case "ok":
	default:
		fmt.Println("Sottoreti di Active Directory:", orDash(r.Error))
		return
	}
	if len(r.Subnets) == 0 {
		fmt.Println("Nessuna sottorete definita in Siti e servizi di Active Directory.")
		return
	}
	fmt.Println("Sottoreti definite in Active Directory (Siti e servizi):")
	for _, s := range r.Subnets {
		fmt.Printf("  %-20s %s\n", s.Prefix, s.Site)
	}
}

var snmpState = map[string]string{
	snmp.StateOK:      "letta",
	snmp.StatePartial: "letta in parte",
	snmp.StateAbsent:  "non gestita",
	snmp.StateError:   "errore",
	snmp.StateSkipped: "non letta",
}

func printSNMP(r *snmp.Result) {
	fmt.Printf("Dispositivo %s, SNMPv%s, %d richieste in %.1f secondi\n", r.Target, r.Version, r.Requests, float64(r.DurationMs)/1000)
	if s := r.System; s != nil {
		if s.Name != "" {
			fmt.Printf("  Nome: %s\n", s.Name)
		}
		if s.Descr != "" {
			fmt.Printf("  Descrizione: %s\n", s.Descr)
		}
	}
	for _, w := range r.Warnings {
		fmt.Printf("  Attenzione: %s\n", w)
	}
	if len(r.Vlans) > 0 {
		fmt.Println("\nVLAN configurate:")
		for _, v := range r.Vlans {
			fmt.Printf("  %4d %s\n", v.ID, v.Name)
		}
	}
	nets := 0
	for _, i := range r.Interfaces {
		for _, ip := range i.IPs {
			if nets == 0 {
				fmt.Println("\nReti con un indirizzo sul dispositivo:")
			}
			nets++
			vlan := ""
			if i.VlanID > 0 {
				vlan = fmt.Sprintf(" (VLAN %d)", i.VlanID)
			}
			fmt.Printf("  %-20s %s su %s%s\n", orDash(ip.Subnet), ip.IP, orDash(i.Name), vlan)
		}
	}
	if len(r.LldpNeighbors) > 0 {
		fmt.Println("\nVicini LLDP:")
		for _, n := range r.LldpNeighbors {
			fmt.Printf("  porta %s -> %s %s\n", orDash(n.LocalPort), orDash(n.SysName), n.MgmtIP)
		}
	}
	fmt.Printf("\nTabella ARP: %d righe; indirizzi MAC per porta: %d righe\n", len(r.Arp), len(r.Fdb))
	for _, sec := range []struct {
		name string
		st   snmp.Status
	}{
		{"Dati del dispositivo", r.Sections.System}, {"Interfacce", r.Sections.Interfaces}, {"VLAN", r.Sections.Vlans},
		{"Vicini LLDP", r.Sections.Lldp}, {"ARP", r.Sections.Arp}, {"MAC per porta", r.Sections.Fdb},
	} {
		line := fmt.Sprintf("  %-22s %s", sec.name, orDash(snmpState[sec.st.State]))
		if sec.st.Note != "" {
			line += ": " + sec.st.Note
		}
		fmt.Println(line)
	}
	if r.Stopped != "" {
		fmt.Println("Lettura fermata prima della fine:", r.Stopped)
	}
}
