package pdh

import (
	"errors"
	"fmt"
	"testing"
)

func TestMissing(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&Error{"PdhAddEnglishCounter", CstatusNoObject}, true},
		{fmt.Errorf("apertura: %w", &Error{"PdhAddEnglishCounter", CstatusNoCounter}), true},
		{&Error{"PdhCollectQueryData", 0x800007D5}, false},
		{errors.New("altro"), false},
		{nil, false},
	} {
		if got := Missing(c.err); got != c.want {
			t.Errorf("Missing(%v) = %v", c.err, got)
		}
	}
	if s := (&Error{"PdhOpenQuery", 0xC0000BB8}).Error(); s != "PdhOpenQuery: errore PDH 0xC0000BB8" {
		t.Errorf("messaggio: %q", s)
	}
}
