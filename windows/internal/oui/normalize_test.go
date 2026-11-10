package oui

import "testing"

func TestNormalize(t *testing.T) {
	// Quasi tutti nomi veri dell'elenco IEEE, scritti com'è lì.
	for in, want := range map[string]string{
		// Forme societarie in coda, in tutte le grafie.
		"Apple, Inc.":                    "Apple",
		"Synology Incorporated":          "Synology",
		"Sony Corporation":               "Sony",
		"IBM Corp":                       "IBM",
		"Nintendo Co.,Ltd":               "Nintendo",
		"Murata Manufacturing Co., Ltd.": "Murata Manufacturing",
		"ALPSALPINE CO,.LTD":             "ALPSALPINE",
		"BUFFALO.INC":                    "BUFFALO",
		"Hitron Technologies. Inc":       "Hitron Technologies",
		"Sercomm Corporation.":           "Sercomm",
		"Guangzhou Shiyuan Electronic Technology Company Limited":       "Guangzhou Shiyuan Electronic Technology",
		"Nokia Solutions and Networks GmbH & Co. KG":                    "Nokia Solutions and Networks",
		"Siemens Convergence Creators GmbH&Co.KG":                       "Siemens Convergence Creators",
		"PuS GmbH und Co. KG":                                           "PuS",
		"Vodafone Italia S.p.A.":                                        "Vodafone Italia",
		"BETTINI SRL":                                                   "BETTINI",
		"4neXt S.r.l.s.":                                                "4neXt",
		"Philips Electronics Nederland BV":                              "Philips Electronics Nederland",
		"EchoStar Global B.V.":                                          "EchoStar Global",
		"Nokia Danmark A/S":                                             "Nokia Danmark",
		"Ericsson AB":                                                   "Ericsson",
		"HMD Global Oy":                                                 "HMD Global",
		"Integrated Device Technology (Malaysia) Sdn. Bhd.":             "Integrated Device Technology",
		"AVSystem sp. z o. o.":                                          "AVSystem",
		"CDR Sp. z o.o. Sp. k.":                                         "CDR",
		"Sistemas de Gestión Energética S.A. de C.V":                    "Sistemas de Gestión Energética",
		"Prama Hikvision India Private Limited":                         "Prama Hikvision India",
		"Telenet Systems P. Ltd.":                                       "Telenet Systems",
		"Potter Electric Signal Co. LLC":                                "Potter Electric Signal",
		"Kaspersky Lab Middle-East FZ-LLC":                              "Kaspersky Lab Middle-East",
		"hangzhou soar security technologies limited liability company": "hangzhou soar security technologies",
		"Viettel Manufacturing Corporation One Member Limited Liability Company": "Viettel Manufacturing",
		// Precisazioni tra parentesi in coda, anche senza chiusura.
		"Raspberry Pi (Trading) Ltd":             "Raspberry Pi",
		"SAMSUNG ELECTRO-MECHANICS(THAILAND)":    "SAMSUNG ELECTRO-MECHANICS",
		"ELECOM CO., LTD. (LANEED DIV.)":         "ELECOM",
		"Flextroincs International (Taiwain Ltd": "Flextroincs International",
		// Parentesi in mezzo o lunghe: restano.
		"LCFC(Hefei) Electronics Technology co., ltd":   "LCFC(Hefei) Electronics Technology",
		"杭州德澜科技有限公司（HangZhou Delan Technology Co.,Ltd）": "杭州德澜科技有限公司(HangZhou Delan Technology Co.,Ltd)",
		// Spazi speciali, caratteri invisibili, larghezza piena, byte non validi.
		"Shenzhen YOUHUA Technology Co., Ltd\t":                    "Shenzhen YOUHUA Technology",
		"\t ONE Investment Group Limited":                          "ONE Investment Group",
		"Sichuan\u00a0AI-Link\u00a0Technology\u00a0Co.,\u00a0Ltd.": "Sichuan AI-Link Technology",
		"Toray\u3000Medical\u3000Co.,Ltd":                          "Toray Medical",
		"SHENZHEN\u2002TONG BO WEI\u2002TECHNOLOGY Co.,LTD":        "SHENZHEN TONG BO WEI TECHNOLOGY",
		"\u200bASUNG TECHNO CO.,Ltd":                               "ASUNG TECHNO",
		"Gilbarco Veeder-Root \u200e":                              "Gilbarco Veeder-Root",
		"SHENZHEN BILIAN ELECTRONIC CO.\uff0cLTD":                  "SHENZHEN BILIAN ELECTRONIC",
		"Shenzhen Skyworth Digital  Technology  CO., Ltd":          "Shenzhen Skyworth Digital Technology",
		"Foo\xffBar Inc.":                                          "FooBar",
		"":                                                         "",
		" \t ":                                                     "",
		// Nomi da non rovinare: "Company" fa parte del nome, sigle puntate,
		// società diverse con nomi simili ai marchi, nomi fatti solo di una
		// forma societaria.
		"The Boeing Company":          "The Boeing Company",
		"CT Company":                  "CT Company",
		"Texas Instruments":           "Texas Instruments",
		"Cisco Meraki":                "Cisco Meraki",
		"Cisco-Linksys, LLC":          "Cisco-Linksys",
		"Juniper Systems":             "Juniper Systems",
		"Brother, Brother & Sons ApS": "Brother, Brother & Sons",
		"AVM ELECTRONICS PTE LTD":     "AVM ELECTRONICS",
		"HP Tuners LLC":               "HP Tuners",
		"Amgen U.S.A. Inc.":           "Amgen U.S.A.",
		"KAWASAKI LSI U.S.A., INC.":   "KAWASAKI LSI U.S.A.",
		"S.E.I. CO.,LTD.":             "S.E.I.",
		"D-E-K GmbH & Co.KG":          "D-E-K",
		"ICANN, IANA Department":      "ICANN, IANA Department",
		"Limited":                     "Limited",
		// Alias dei marchi.
		"Hewlett Packard":                                       "HP",
		"Hewlett-Packard":                                       "HP",
		"HP Inc.":                                               "HP",
		"Hewlett Packard Enterprise ":                           "HPE",
		"Cisco Systems, Inc":                                    "Cisco",
		"Samsung Electronics Co.,Ltd":                           "Samsung",
		"SAMSUNG Electronics. Co. LTD":                          "Samsung",
		"Hon Hai Precision Ind. Co.,Ltd.":                       "Foxconn",
		"Hon Hai Precision IND.CO.,LTD":                         "Foxconn",
		"Intel Corporate":                                       "Intel",
		"Intel Corporation":                                     "Intel",
		"Ubiquiti Inc":                                          "Ubiquiti",
		"TP-LINK TECHNOLOGIES CO.,LTD.":                         "TP-Link",
		"TP-Link Systems Inc.":                                  "TP-Link",
		"QNAP Systems, Inc.":                                    "QNAP",
		"Espressif Systems (Singapore) Pte. Ltd":                "Espressif",
		"Raspberry Pi Foundation":                               "Raspberry Pi",
		"AVM Audiovisuelles Marketing und Computersysteme GmbH": "AVM",
		"Technicolor CH USA Inc for Telus":                      "Technicolor",
		"Vantiva USA LLC":                                       "Vantiva",
		"Sagemcom Broadband SAS":                                "Sagemcom",
		"HUAWEI TECHNOLOGIES CO.,LTD":                           "Huawei",
		"Huawei Device Co., Ltd.":                               "Huawei",
		"Hangzhou Hikvision Digital Technology Co.,Ltd.":        "Hikvision",
		"Zhejiang Dahua Technology Co., Ltd.":                   "Dahua",
		"ZHEJIANG DAHUA TECHNOLOGYCO.,LTD":                      "Dahua",
		"Brother industries, LTD.":                              "Brother",
		"Seiko Epson Corporation":                               "Epson",
		"CANON INC.":                                            "Canon",
		"KYOCERA Document Solutions Inc.":                       "Kyocera",
		"XEROX CORPORATION":                                     "Xerox",
		"LEXMARK INTERNATIONAL, INC.":                           "Lexmark",
		"RICOH COMPANY, LTD.":                                   "Ricoh",
		"KONICA MINOLTA HOLDINGS, INC.":                         "Konica Minolta",
		"Zebra Technologies Inc.":                               "Zebra",
		"Juniper Networks":                                      "Juniper",
		"Fortinet, Inc.":                                        "Fortinet",
		"Routerboard.com":                                       "MikroTik",
		"Zyxel Communications Corporation":                      "Zyxel",
		"D-Link International":                                  "D-Link",
		"D-Link (Shanghai) Limited Corp.":                       "D-Link",
		"NETGEAR":                                               "Netgear",
		"Dell Inc.":                                             "Dell",
		"LENOVO(BEIJING)CO., LTD.":                              "Lenovo",
		"MICROSOFT CORP.":                                       "Microsoft",
		"VMware, Inc.":                                          "VMware",
		"Xiaomi Communications Co Ltd":                          "Xiaomi",
		"Google, Inc.":                                          "Google",
		"Amazon Technologies Inc.":                              "Amazon",
		"SONOS Co., Ltd.":                                       "Sonos",
		"Shelly Europe LTD":                                     "Shelly",
		"Philips Medical Systems - Cardiac and Monitoring Systems (CM": "Philips Medical",
		"GE Healthcare":                           "GE Healthcare",
		"Mindray Co., Ltd.":                       "Mindray",
		"Mindray DS USA, Inc.":                    "Mindray",
		"SIEMENS AG":                              "Siemens",
		"Motorola Mobility LLC, a Lenovo Company": "Motorola Mobility",
		"zte corporation":                         "ZTE",
		"ASUSTek COMPUTER INC.":                   "ASUS",
	} {
		got := Normalize(in)
		if got != want {
			t.Errorf("Normalize(%q) = %q, atteso %q", in, got, want)
		}
		if again := Normalize(got); again != got {
			t.Errorf("Normalize(%q) = %q: applicata due volte cambia", got, again)
		}
	}
}

// Ogni alias è scritto come risulta dopo aver tolto forme societarie e
// parentesi (altrimenti non scatterebbe mai), ha una chiave sola e porta a un
// nome che Normalize lascia com'è.
func TestAliasList(t *testing.T) {
	if len(aliases) != len(aliasList) {
		t.Errorf("chiavi ripetute: %d alias, %d chiavi", len(aliasList), len(aliases))
	}
	for _, a := range aliasList {
		if k := aliasKey(trimForms(clean(a.from))); k != aliasKey(a.from) {
			t.Errorf("alias %q: dopo la pulizia diventa %q", a.from, k)
		}
		if got := Normalize(a.from); got != a.to {
			t.Errorf("Normalize(%q) = %q, atteso %q", a.from, got, a.to)
		}
		if got := Normalize(a.to); got != a.to {
			t.Errorf("Normalize(%q) = %q: il marchio cambia", a.to, got)
		}
	}
}
