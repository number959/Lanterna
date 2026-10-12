package netsh

import "testing"

const english = `
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 2b9b0e73-1d2c-4e5f-8a9b-0c1d2e3f4a5b
    Physical address       : 3c:58:c2:aa:bb:cc
    Interface type         : Primary
    State                  : connected
    SSID                   : Casa: Rossi
    AP BSSID               : A4:2B:B0:11:22:33
    Band                   : 5 GHz
    Channel                : 36
    Connected Akm-cipher   : [ akm = 00-0f-ac:02, cipher = 00-0f-ac:04 ]
    Link Quality           : 95%
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1081
    Signal                 : 95%
    Rssi                   : -45
    Profile                : Casa: Rossi

    Hosted network status  : Not available
`

// Output italiano come arriva leggendo CP850 come se fosse Latin-1:
// "à" diventa "Ó" e "è" diventa "Þ".
const italianCP850 = "\r\nNel sistema Þ presente 2 interfacce:\r\n\r\n" +
	"    Nome                   : Wi-Fi 2\r\n" +
	"    Descrizione            : Realtek USB\r\n" +
	"    Stato                  : disconnessa\r\n" +
	"\r\n" +
	"    Nome                   : Wi-Fi\r\n" +
	"    Descrizione            : Intel(R) Wireless-AC 9560\r\n" +
	"    Stato                  : connessa\r\n" +
	"    SSID                   : TIM-29384756\r\n" +
	"    BSSID                  : 30:91:8f:aa:bb:01\r\n" +
	"    Tipo di rete           : Infrastruttura\r\n" +
	"    Tipo frequenza radio   : 802.11n\r\n" +
	"    Autenticazione         : WPA2-Personal\r\n" +
	"    Crittografia           : CCMP\r\n" +
	"    ModalitÓ connessione   : Connessione automatica\r\n" +
	"    Canale                 : 6\r\n" +
	"    VelocitÓ ricezione (Mbps)  : 144,4\r\n" +
	"    VelocitÓ trasmissione (Mbps) : 72\r\n" +
	"    Segnale                : 62%\r\n" +
	"    Profilo                : TIM-29384756\r\n"

func TestEnglish(t *testing.T) {
	list := ParseInterfaces(english)
	if len(list) != 1 {
		t.Fatalf("%d schede", len(list))
	}
	c := Connected(list)
	if c == nil || c.SSID != "Casa: Rossi" || c.BSSID != "a4:2b:b0:11:22:33" || c.Band != "5" || c.Channel != 36 {
		t.Fatalf("%+v", c)
	}
	if c.Radio != "802.11ax" || c.Auth != "WPA2-Personal" || c.Cipher != "CCMP" || c.RxMbps != 1201 || c.TxMbps != 1081 {
		t.Fatalf("%+v", c)
	}
	if c.SignalPct == nil || *c.SignalPct != 95 || c.RssiDbm == nil || *c.RssiDbm != -45 {
		t.Fatalf("segnale: %+v", c)
	}
}

func TestItalianMangled(t *testing.T) {
	list := ParseInterfaces(italianCP850)
	if len(list) != 2 || list[0].Connected {
		t.Fatalf("%+v", list)
	}
	c := Connected(list)
	if c == nil || c.Name != "Wi-Fi" || c.SSID != "TIM-29384756" || c.Channel != 6 || c.Radio != "802.11n" {
		t.Fatalf("%+v", c)
	}
	if c.RxMbps != 144.4 || c.TxMbps != 72 || *c.SignalPct != 62 || c.RssiDbm != nil || c.Band != "" {
		t.Fatalf("%+v", c)
	}
}

func TestNoInterfaces(t *testing.T) {
	if Connected(ParseInterfaces("There is no wireless interface on the system.")) != nil {
		t.Fatal("nessuna scheda attesa")
	}
}

func TestLocationDenied(t *testing.T) {
	msg := "Network shell commands need location permission to access WLAN information. Turn on Location services on the Location page in Privacy & security settings.\n\nHere is the URI for the Location page in the Settings app:\nms-settings:privacy-location"
	if !LocationDenied(msg) || LocationDenied(english) {
		t.Fatal("riconoscimento del rifiuto per posizione errato")
	}
}
