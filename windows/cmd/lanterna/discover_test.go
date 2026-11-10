package main

import (
	"strings"
	"testing"

	"lanterna/internal/l2disc"
	"lanterna/internal/netdisc"
	"lanterna/internal/snmp"
)

func TestSNMPCredsFromInput(t *testing.T) {
	for _, env := range []string{"POLARIS_SNMP_COMMUNITY", "POLARIS_SNMP_USER", "POLARIS_SNMP_AUTH_PASS", "POLARIS_SNMP_PRIV_PASS"} {
		t.Setenv(env, "")
	}
	cr, err := snmpCreds(false, "", "", strings.NewReader("segreta\r\n"))
	if err != nil || cr.Version != "2c" || cr.Community != "segreta" {
		t.Fatalf("v2c: %v %#v", err, cr)
	}
	if _, err := snmpCreds(false, "SHA", "", strings.NewReader("x\n")); err == nil {
		t.Fatal("--auth senza --v3 accettato")
	}
	if _, err := snmpCreds(false, "", "", strings.NewReader("")); err == nil {
		t.Fatal("ingresso vuoto accettato")
	}
	// SNMPv3 da una pipe: tre righe, tre risposte (un solo lettore).
	cr, err = snmpCreds(true, "SHA256", "AES", strings.NewReader("tecnico\npassword-auth\npassword-priv\n"))
	if err != nil || cr.User != "tecnico" || cr.AuthPass != "password-auth" || cr.PrivPass != "password-priv" {
		t.Fatalf("v3 da pipe: %v %#v", err, cr)
	}
	// SNMPv3: utente e password dalle variabili d'ambiente, nessuna domanda.
	t.Setenv("POLARIS_SNMP_USER", "tecnico")
	t.Setenv("POLARIS_SNMP_AUTH_PASS", "password-auth")
	t.Setenv("POLARIS_SNMP_PRIV_PASS", "password-priv")
	cr, err = snmpCreds(true, "sha256", "aes", strings.NewReader(""))
	if err != nil || cr.Version != "3" || cr.User != "tecnico" || cr.Auth != "SHA256" || cr.Priv != "AES" || cr.AuthPass != "password-auth" || cr.PrivPass != "password-priv" {
		t.Fatalf("v3: %v %#v", err, cr)
	}
	// La descrizione delle credenziali non contiene mai i segreti.
	if s := cr.String(); strings.Contains(s, "tecnico") || strings.Contains(s, "password-") {
		t.Fatalf("segreti nella descrizione: %s", s)
	}
}

func TestDiscoverPrintersEmpty(t *testing.T) {
	// Nessun pannico con risultati vuoti o parziali.
	printRoutes(nil)
	printRoutes([]netdisc.Route{{Prefix: "10.20.0.0/16", NextHop: "192.168.1.1", Origin: "dhcp"}})
	for _, r := range []string{l2disc.ReadNone, l2disc.ReadAdmin, l2disc.ReadNoWired, l2disc.ReadUnsupported, l2disc.ReadOK} {
		printL2(l2disc.Discovery{Read: r})
	}
	printL2(l2disc.Discovery{Read: l2disc.ReadOK, Lldp: []l2disc.LLDPNeighbor{{ChassisID: "00:11:22:33:44:55", PortVlanID: 20}}, Stp: []l2disc.STPInfo{{Vlan: 30}, {Vlan: 10}}})
	printAD(netdisc.ADSubnets{Read: "nodomain"})
	printAD(netdisc.ADSubnets{Read: "ok", Subnets: []netdisc.ADSubnet{{Prefix: "10.1.0.0/16", Site: "Sede"}}})
	printAD(netdisc.ADSubnets{Read: "unreachable", Error: "non risponde"})
	printSNMP(&snmp.Result{Target: "10.0.0.2", Version: "3"})
}
