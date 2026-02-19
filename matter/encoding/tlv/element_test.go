package tlv

import (
	"math"
	"testing"
)

func TestElementSignedUnsignedVariants(t *testing.T) {
	ptrInt64 := func(v int64) *int64 { return &v }
	ptrUint64 := func(v uint64) *uint64 { return &v }

	// Signed1
	e := &elementImpl{signedValue: ptrInt64(127)}
	if v, ok := e.Signed1(); !ok || v != 127 {
		t.Errorf("Signed1: got %v, %v; want 127, true", v, ok)
	}
	e.signedValue = ptrInt64(128)
	if _, ok := e.Signed1(); ok {
		t.Error("Signed1: expected false for out-of-range value")
	}
	// Signed2
	e.signedValue = ptrInt64(32767)
	if v, ok := e.Signed2(); !ok || v != 32767 {
		t.Errorf("Signed2: got %v, %v; want 32767, true", v, ok)
	}
	e.signedValue = ptrInt64(32768)
	if _, ok := e.Signed2(); ok {
		t.Error("Signed2: expected false for out-of-range value")
	}
	// Signed4
	e.signedValue = ptrInt64(math.MaxInt32)
	if v, ok := e.Signed4(); !ok || v != math.MaxInt32 {
		t.Errorf("Signed4: got %v, %v; want %v, true", v, ok, math.MaxInt32)
	}
	e.signedValue = ptrInt64(math.MaxInt32 + 1)
	if _, ok := e.Signed4(); ok {
		t.Error("Signed4: expected false for out-of-range value")
	}
	// Signed8
	e.signedValue = ptrInt64(math.MaxInt64)
	if v, ok := e.Signed8(); !ok || v != math.MaxInt64 {
		t.Errorf("Signed8: got %v, %v; want %v, true", v, ok, int64(math.MaxInt64))
	}

	// Unsigned1
	e.unsignedValue = ptrUint64(255)
	if v, ok := e.Unsigned1(); !ok || v != 255 {
		t.Errorf("Unsigned1: got %v, %v; want 255, true", v, ok)
	}
	e.unsignedValue = ptrUint64(256)
	if _, ok := e.Unsigned1(); ok {
		t.Error("Unsigned1: expected false for out-of-range value")
	}
	// Unsigned2
	e.unsignedValue = ptrUint64(65535)
	if v, ok := e.Unsigned2(); !ok || v != 65535 {
		t.Errorf("Unsigned2: got %v, %v; want 65535, true", v, ok)
	}
	e.unsignedValue = ptrUint64(65536)
	if _, ok := e.Unsigned2(); ok {
		t.Error("Unsigned2: expected false for out-of-range value")
	}
	// Unsigned4
	e.unsignedValue = ptrUint64(math.MaxUint32)
	if v, ok := e.Unsigned4(); !ok || v != math.MaxUint32 {
		t.Errorf("Unsigned4: got %v, %v; want %v, true", v, ok, uint32(math.MaxUint32))
	}
	e.unsignedValue = ptrUint64(math.MaxUint32 + 1)
	if _, ok := e.Unsigned4(); ok {
		t.Error("Unsigned4: expected false for out-of-range value")
	}
	// Unsigned8
	e.unsignedValue = ptrUint64(math.MaxUint64)
	if v, ok := e.Unsigned8(); !ok || v != math.MaxUint64 {
		t.Errorf("Unsigned8: got %v, %v; want %v, true", v, ok, uint64(math.MaxUint64))
	}
}
