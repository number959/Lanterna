package sensors

import (
	"encoding/binary"
	"math"
)

// Costanti di batclass.h e poclass.h (classe batteria di Windows).
const (
	batteryCapacityRelative = 0x40000000 // capacità e potenza in unità relative, non in mWh e mW
	batterySystemBattery    = 0x80000000 // batteria che alimenta il PC
	batteryIsShortTerm      = 0x20000000 // riserva di breve durata, come un gruppo di continuità
	batteryPowerOnLine      = 0x00000001
	batteryDischarging      = 0x00000002
	batteryCharging         = 0x00000004
	batteryUnknownCapacity  = 0xFFFFFFFF
	batteryUnknownVoltage   = 0xFFFFFFFF
	batteryUnknownRate      = 0x80000000

	// BATTERY_INFORMATION: Capabilities a +0, DesignedCapacity a +12,
	// FullChargedCapacity a +16 (36 byte in tutto).
	batteryInfoSize = 36
	// BATTERY_STATUS: PowerState, Capacity (mWh), Voltage (mV), Rate (mW
	// con segno), 16 byte.
	batteryStatusSize = 16
)

// parseBattery combina BATTERY_INFORMATION e BATTERY_STATUS; tempTenthsK è la
// temperatura in decimi di kelvin (0: non letta). false se i dati non sono
// utilizzabili o se non è la batteria del PC: come nell'esempio di Microsoft
// si escludono i gruppi di continuità, che stanno nella stessa classe.
func parseBattery(name string, info, status []byte, tempTenthsK uint32) (Battery, bool) {
	if len(info) < batteryInfoSize || len(status) < batteryStatusSize {
		return Battery{}, false
	}
	le := binary.LittleEndian
	caps := le.Uint32(info[0:])
	if caps&batterySystemBattery == 0 || caps&batteryIsShortTerm != 0 {
		return Battery{}, false
	}
	design, full := le.Uint32(info[12:]), le.Uint32(info[16:])
	state, capacity, mv, rate := le.Uint32(status[0:]), le.Uint32(status[4:]), le.Uint32(status[8:]), le.Uint32(status[12:])
	b := Battery{Name: name, ChargePct: nan, CapacityWh: nan, FullWh: nan, DesignWh: nan, RateW: nan, VoltageV: nan, TempC: nan,
		OnLine: state&batteryPowerOnLine != 0, Discharging: state&batteryDischarging != 0, Charging: state&batteryCharging != 0}
	relative := caps&batteryCapacityRelative != 0
	if capacity != batteryUnknownCapacity && full != batteryUnknownCapacity && full > 0 {
		b.ChargePct = math.Min(100, 100*float64(capacity)/float64(full))
	}
	if !relative {
		if capacity != batteryUnknownCapacity {
			b.CapacityWh = float64(capacity) / 1000
		}
		if full != batteryUnknownCapacity && full > 0 {
			b.FullWh = float64(full) / 1000
		}
		if design != batteryUnknownCapacity && design > 0 {
			b.DesignWh = float64(design) / 1000
		}
		if rate != batteryUnknownRate {
			b.RateW = float64(int32(rate)) / 1000
		}
	}
	if mv != batteryUnknownVoltage && mv > 0 {
		b.VoltageV = float64(mv) / 1000
	}
	if tempTenthsK > 0 {
		b.TempC = float64(tempTenthsK)/10 - 273.15
	}
	return b, ok(b.ChargePct) || ok(b.CapacityWh)
}
