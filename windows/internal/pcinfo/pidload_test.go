package pcinfo

import (
	"testing"
	"time"
)

func TestCPUByPID(t *testing.T) {
	before := []ProcSample{{PID: 10, Name: "a.exe", CPU: 1000}, {PID: 20, Name: "b.exe", CPU: 5000}, {PID: 30, Name: "c.exe", CPU: 900}, {PID: 40, Name: "d.exe", CPU: 100}}
	after := []ProcSample{
		{PID: 10, Name: "a.exe", CPU: 1000 + 3_000_000}, // 0,3 s di CPU in 1 s su 2 processori: 15 %
		{PID: 20, Name: "b.exe", CPU: 5000},             // fermo: 0 %
		{PID: 30, Name: "nuovo.exe", CPU: 50},           // PID riutilizzato: non misurato
		{PID: 50, Name: "e.exe", CPU: 999},              // nato durante la misura: non misurato
	}
	m := CPUByPID(before, after, time.Second, 2)
	if len(m) != 2 || m[10] != 15 || m[20] != 0 {
		t.Fatalf("%v", m)
	}
	if _, ok := m[30]; ok {
		t.Fatal("PID riutilizzato misurato")
	}
	if len(CPUByPID(before, after, 0, 2)) != 0 {
		t.Fatal("durata nulla")
	}
}
