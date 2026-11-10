package l2disc

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClean(t *testing.T) {
	cases := map[string]string{
		"  a\x00b\r\nc\t ":    "a b c",
		"\xffabc":             "\uFFFDabc",
		"\u202Eevil\u200B!":   "evil !",
		"rete\u00A0ospiti":    "rete ospiti",
		"":                    "",
		"\x00\x00":            "",
		"Città di Castello\n": "Città di Castello",
	}
	for in, want := range cases {
		if got := clean([]byte(in)); got != want {
			t.Errorf("clean(%q) = %q, atteso %q", in, got, want)
		}
	}
	long := clean([]byte(strings.Repeat("è", 300)))
	if utf8.RuneCountInString(long) != maxRunes || !strings.HasSuffix(long, "…") {
		t.Fatalf("testo lungo non accorciato: %d", utf8.RuneCountInString(long))
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine([]byte("\r\n \nprima riga\r\nseconda")); got != "prima riga" {
		t.Fatalf("%q", got)
	}
	if got := firstLine([]byte("\n\n")); got != "" {
		t.Fatalf("%q", got)
	}
}

func TestStripSerials(t *testing.T) {
	cases := map[string]string{
		"SW-CORE(FOC1234X5YZ)":    "SW-CORE",
		"N9K-A (SAL1234ABCD).lan": "N9K-A.lan",
		"Core (Stack-01)":         "Core (Stack-01)",
		"Sala(BUILDING2)":         "Sala(BUILDING2)",
		"S248DF3X17000123":        "",
		"FGT60E4Q16000000":        "",
		"SEP001122334455":         "SEP001122334455",
		"001122AABBCC":            "001122AABBCC",
		"CORE3850A01":             "CORE3850A01",
		"SWITCH01":                "SWITCH01",
		"switch-lab":              "switch-lab",
		"Switch S/N: FOC1234X5YZ": "Switch S/N: …",
		"serial console":          "serial console",
		"Serial Number ABC12345":  "Serial Number …",
	}
	for in, want := range cases {
		if got := stripSerials(in); got != want {
			t.Errorf("stripSerials(%q) = %q, atteso %q", in, got, want)
		}
	}
}

func TestDescriptionsKeepParentheses(t *testing.T) {
	// Le descrizioni conservano le parentesi (immagine del software), ma non
	// i numeri di serie con l'etichetta.
	in := "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), SN: FOC1234X5YZ, Version 15.2"
	want := "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), SN: …, Version 15.2"
	if got := descText([]byte(in)); got != want {
		t.Fatalf("%q", got)
	}
}

func TestHexColonIsCapped(t *testing.T) {
	h := hexColon(make([]byte, 255))
	if utf8.RuneCountInString(h) != maxRunes || !strings.HasPrefix(h, "00:00") {
		t.Fatalf("%q", h)
	}
	if hexColon(nil) != "" {
		t.Fatal("vuoto")
	}
}
