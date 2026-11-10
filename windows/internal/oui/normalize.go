package oui

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Normalize riduce il nome di un'organizzazione, come lo scrive la IEEE, a una
// forma breve vicina al marchio, da mostrare accanto a un dispositivo:
//   - spazi ripuliti (anche quelli speciali come U+00A0 e U+3000), caratteri
//     invisibili tolti, punteggiatura a larghezza piena ("，", "（") resa con
//     l'equivalente ASCII;
//   - tolte in coda le forme societarie (Inc., Co., Ltd., Corp., GmbH, S.p.A.,
//     S.r.l., B.V., AG, LLC, Limited, plc...) e una precisazione breve tra
//     parentesi ("Raspberry Pi (Trading)", "Lenovo (Beijing)");
//   - per i produttori più comuni, il nome del marchio (aliasList).
//
// Le parole descrittive (Technologies, Systems, Electronics...) restano: fanno
// spesso parte del nome vero ("Advanced Technology", "The Boeing Company") e
// per i marchi noti provvede la tabella degli alias. Applicata due volte dà lo
// stesso risultato. Il generatore di oui.txt.gz la applica a ogni voce.
func Normalize(name string) string {
	s := trimForms(clean(name))
	if a, ok := aliases[aliasKey(s)]; ok {
		return a
	}
	return s
}

// clean toglie i caratteri invisibili e di controllo, rende con l'equivalente
// ASCII le forme a larghezza piena (U+FF01-U+FF5E, come la virgola "，" di
// molti nomi cinesi) e riduce ogni sequenza di spazi a uno spazio solo.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 0xFF01 && r <= 0xFF5E:
			return r - 0xFEE0
		case unicode.IsSpace(r):
			return ' '
		case r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// trimForms toglie dalla coda del nome, finché ce ne sono, le forme societarie
// e le precisazioni brevi tra parentesi, lasciando sempre almeno una parola.
func trimForms(s string) string {
	s = trimTail(s)
	for {
		if t, ok := cutParen(s); ok {
			s = t
			continue
		}
		if t, ok := cutLegal(s); ok {
			s = t
			continue
		}
		return s
	}
}

// trimTail toglie spazi e punteggiatura di separazione in coda ("Foo Co.,"
// diventa "Foo Co", "GmbH &" diventa "GmbH"). Il punto finale delle sigle
// puntate resta ("S.E.I.", "U.S.A.").
func trimTail(s string) string {
	for s != "" {
		r, size := utf8.DecodeLastRuneInString(s)
		if (r != ' ' && !strings.ContainsRune(",.;:&-\u2013\u2014/", r)) || (r == '.' && initial(s[:len(s)-size])) {
			break
		}
		s = s[:len(s)-size]
	}
	return s
}

// initial dice se s finisce con una lettera isolata, cioè l'iniziale di una
// sigla ("S.E.I", "U.S.A").
func initial(s string) bool {
	r, size := utf8.DecodeLastRuneInString(s)
	if !unicode.IsLetter(r) {
		return false
	}
	p, _ := utf8.DecodeLastRuneInString(s[:len(s)-size])
	return len(s) == size || !isWord(p)
}

// isWord dice se il carattere fa parte di una parola: lettere e cifre.
func isWord(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// words conta le parole (sequenze di lettere e cifre) di s.
func words(s string) int {
	n, in := 0, false
	for _, r := range s {
		w := isWord(r)
		if w && !in {
			n++
		}
		in = w
	}
	return n
}

// maxParenWords è il numero massimo di parole di una precisazione tra
// parentesi da togliere: più lunga, di solito è il nome stesso in un'altra
// lingua ("杭州德澜科技有限公司(HangZhou Delan Technology Co.,Ltd)") e resta.
const maxParenWords = 3

// cutParen toglie la precisazione tra parentesi che chiude il nome
// ("Lenovo (Beijing)", "SAMSUNG ELECTRO-MECHANICS(THAILAND)"), anche quando
// nell'elenco manca la parentesi di chiusura ("Flextroincs International
// (Taiwain").
func cutParen(s string) (string, bool) {
	open := -1
	if strings.HasSuffix(s, ")") {
		depth := 0
		for i := len(s) - 1; i >= 0 && open < 0; i-- {
			switch s[i] {
			case ')':
				depth++
			case '(':
				if depth--; depth == 0 {
					open = i
				}
			}
		}
	} else if i := strings.LastIndexByte(s, '('); i >= 0 && strings.IndexByte(s[i:], ')') < 0 {
		open = i
	}
	if open < 0 {
		return s, false
	}
	head := trimTail(s[:open])
	if words(s[open:]) > maxParenWords || words(head) == 0 {
		return s, false
	}
	return head, true
}

// legalForms sono le forme societarie che si tolgono dalla coda del nome,
// parola per parola in minuscolo, senza punteggiatura: "S.p.A." è "s p a",
// "Co.,Ltd." si toglie in due passi ("ltd", poi "co"). "Company" da sola non
// c'è: fa parte di nomi come "The Boeing Company".
var legalForms = [][]string{
	// Più parole: vanno provate prima delle forme che contengono.
	{"one", "member", "limited", "liability", "company"},
	{"limited", "liability", "company"},
	{"joint", "stock", "company"},
	{"company", "limited"}, {"company", "ltd"}, {"limited", "company"},
	{"private", "limited"}, {"p", "limited"}, {"p", "ltd"},
	{"sdn", "bhd"},
	{"und", "co"}, {"u", "co"},
	{"s", "a", "de", "c", "v"}, {"sa", "de", "cv"}, {"de", "c", "v"},
	{"sp", "z", "o", "o"}, {"sp", "k"}, {"sp", "j"},
	{"s", "r", "l", "s"}, {"g", "m", "b", "h"},
	{"s", "p", "a"}, {"s", "r", "l"}, {"s", "a", "s"}, {"s", "a", "u"}, {"s", "l", "u"},
	{"m", "b", "h"}, {"s", "r", "o"}, {"l", "l", "c"}, {"d", "o", "o"},
	{"s", "a"}, {"s", "l"}, {"b", "v"}, {"n", "v"}, {"l", "p"}, {"k", "k"},
	{"a", "s"}, {"a", "ş"}, {"e", "k"},
	{"fz", "llc"},
	{"ltd", "şti"}, {"ltd", "sti"},
	// Una parola.
	{"inc"}, {"incorporated"}, {"corp"}, {"corporation"}, {"co"},
	{"ltd"}, {"limited"}, {"llc"}, {"llp"}, {"plc"}, {"lp"},
	{"gmbh"}, {"mbh"}, {"ag"}, {"kg"}, {"kgaa"}, {"se"},
	{"spa"}, {"srl"}, {"srls"}, {"sa"}, {"sas"}, {"sarl"}, {"sau"}, {"sl"}, {"slu"},
	{"bv"}, {"nv"}, {"ab"}, {"oy"}, {"oyj"}, {"as"}, {"asa"}, {"aps"},
	{"kft"}, {"zrt"}, {"sro"}, {"bhd"}, {"berhad"}, {"pty"}, {"pte"}, {"pvt"},
	{"ltda"}, {"lda"}, {"kk"}, {"jsc"}, {"eood"}, {"ood"}, {"fzco"}, {"fze"},
}

// maxForm è la lunghezza in parole della forma societaria più lunga.
const maxForm = 5

// cutLegal toglie la forma societaria che chiude il nome, se prima resta
// almeno una parola. Dopo la forma può esserci solo punteggiatura (".", ","):
// in "Foo (Bar Ltd)" la forma è dentro una parentesi e resta.
func cutLegal(s string) (string, bool) {
	// Ultime parole del nome, dall'ultima: testo in minuscolo, inizio e
	// separatore che la segue.
	var tail [maxForm + 1]string
	var start [maxForm + 1]int
	var after [maxForm + 1]string
	n, end := 0, len(s)
	for n < len(tail) {
		i := end
		for i > 0 {
			r, size := utf8.DecodeLastRuneInString(s[:i])
			if isWord(r) {
				break
			}
			if n == 0 && r != '.' && r != ',' {
				return s, false
			}
			i -= size
		}
		if i == 0 {
			break
		}
		j := i
		for j > 0 {
			r, size := utf8.DecodeLastRuneInString(s[:j])
			if !isWord(r) {
				break
			}
			j -= size
		}
		tail[n], start[n], after[n] = strings.ToLower(s[j:i]), j, s[i:end]
		n++
		end = j
	}
next:
	for _, f := range legalForms {
		if len(f) >= n {
			continue
		}
		for k, w := range f {
			x := len(f) - 1 - k
			if tail[x] != w {
				continue next
			}
			// Le iniziali di una forma ("S.p.A.", "A/S") sono separate solo
			// da punti, barre, virgole e spazi: "D-E-K" non è "e.K.".
			if k > 0 && (utf8.RuneCountInString(w) == 1 || utf8.RuneCountInString(f[k-1]) == 1) &&
				strings.Trim(after[x+1], "./, ") != "" {
				continue next
			}
		}
		// Una forma che comincia con un'iniziale non deve essere la coda di
		// una sigla più lunga: in "U.S.A." non c'è "S.A.".
		if k := len(f); utf8.RuneCountInString(tail[k-1]) == 1 && utf8.RuneCountInString(tail[k]) == 1 &&
			strings.Trim(after[k], ".") == "" {
			continue
		}
		return trimTail(s[:start[len(f)-1]]), true
	}
	return s, false
}

// aliasKey è la chiave di confronto per gli alias: solo lettere e cifre, in
// minuscolo ("Hewlett-Packard" e "Hewlett Packard" coincidono).
func aliasKey(s string) string {
	return strings.Map(func(r rune) rune {
		if isWord(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, s)
}

// aliasList porta al nome del marchio i nomi più comuni dell'elenco IEEE, come
// risultano dopo aver tolto forme societarie e precisazioni tra parentesi
// (il confronto ignora maiuscole, spazi e punteggiatura). Ogni voce
// corrisponde ad almeno un nome dell'elenco del 10 novembre 2026; le società
// diverse con nomi simili restano distinte ("Brother, Brother & Sons",
// "Juniper Systems", "AVM ELECTRONICS", "HP Tuners").
var aliasList = []struct{ from, to string }{
	{"Hewlett Packard", "HP"},
	{"Hewlett Packard Enterprise", "HPE"},
	{"Cisco Systems", "Cisco"},
	{"Samsung Electronics", "Samsung"},
	{"Hon Hai Precision Ind", "Foxconn"},
	{"Hon Hai Precision Industry", "Foxconn"},
	{"HON HAI-CCPBG PRECISION IND", "Foxconn"},
	{"FOXCONN", "Foxconn"},
	{"Intel Corporate", "Intel"},
	{"TP-LINK TECHNOLOGIES", "TP-Link"},
	{"TP-Link Systems", "TP-Link"},
	{"Hangzhou Hikvision Digital Technology", "Hikvision"},
	{"Zhejiang Dahua Technology", "Dahua"},
	{"ZHEJIANG DAHUA TECHNOLOGYCO", "Dahua"}, // così nell'elenco IEEE
	{"QNAP Systems", "QNAP"},
	{"Espressif Systems", "Espressif"},
	{"Raspberry Pi Trading", "Raspberry Pi"},
	{"Raspberry Pi Foundation", "Raspberry Pi"},
	{"AVM Audiovisuelles Marketing und Computersysteme", "AVM"},
	{"Technicolor (China) Technology", "Technicolor"},
	{"Technicolor CH USA Inc for Telus", "Technicolor"},
	// Vantiva è il nome attuale di Technicolor per modem e decoder
	// (Connected Home): l'elenco usa ancora entrambi i nomi.
	{"Vantiva USA", "Vantiva"},
	{"Vantiva Technologies Belgium", "Vantiva"},
	{"Vantiva - Connected Home", "Vantiva"},
	{"Sagemcom Broadband", "Sagemcom"},
	{"HUAWEI TECHNOLOGIES", "Huawei"},
	{"Huawei Device", "Huawei"},
	{"Brother Industries", "Brother"},
	{"Seiko Epson", "Epson"},
	{"CANON", "Canon"},
	{"KYOCERA", "Kyocera"},
	{"KYOCERA Document Solutions", "Kyocera"},
	{"XEROX", "Xerox"},
	{"LEXMARK INTERNATIONAL", "Lexmark"},
	{"RICOH", "Ricoh"},
	{"KONICA MINOLTA HOLDINGS", "Konica Minolta"},
	{"Zebra Technologies", "Zebra"},
	{"Juniper Networks", "Juniper"},
	{"Routerboard.com", "MikroTik"},
	{"Zyxel Communications", "Zyxel"},
	{"D-Link International", "D-Link"},
	{"D-LINK SYSTEMS", "D-Link"},
	{"NETGEAR", "Netgear"},
	{"Dell Technologies", "Dell"},
	{"LENOVO", "Lenovo"},
	{"MICROSOFT", "Microsoft"},
	{"Xiaomi Communications", "Xiaomi"},
	{"Beijing Xiaomi Mobile Software", "Xiaomi"},
	{"Beijing Xiaomi Electronics", "Xiaomi"},
	{"XIAOMI Electronics", "Xiaomi"},
	{"Amazon Technologies", "Amazon"},
	{"Amazon.com", "Amazon"},
	{"SONOS", "Sonos"},
	{"Shelly Europe", "Shelly"},
	{"Philips Medical Systems - Cardiac and Monitoring Systems", "Philips Medical"},
	{"Mindray DS USA", "Mindray"},
	{"Mindray North America", "Mindray"},
	{"SIEMENS", "Siemens"},
	{"Motorola Mobility LLC, a Lenovo Company", "Motorola Mobility"},
	{"zte", "ZTE"},
	{"ASUSTek COMPUTER", "ASUS"},
}

var aliases = func() map[string]string {
	m := make(map[string]string, len(aliasList))
	for _, a := range aliasList {
		m[aliasKey(a.from)] = a.to
	}
	return m
}()
