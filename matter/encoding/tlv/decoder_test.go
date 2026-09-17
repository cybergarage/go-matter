package tlv

import (
	"testing"
)

// TestDecoderSurfacesEndOfContainer verifies that Next()/Element() yield
// EndOfContainer markers to the caller (rather than silently swallowing them),
// which is required to correctly walk nested, variable-length containers such
// as a List of Structures.
func TestDecoderSurfacesEndOfContainer(t *testing.T) {
	enc := NewEncoder()
	enc.BeginStructure(NewAnonymousTag())
	enc.PutUnsigned1(NewContextTag(1), 0xAA)
	enc.BeginList(NewContextTag(2))
	enc.BeginStructure(NewAnonymousTag())
	enc.PutUnsigned1(NewContextTag(1), 1)
	if err := enc.EndContainer(); err != nil { // end inner structure #1
		t.Fatal(err)
	}
	enc.BeginStructure(NewAnonymousTag())
	enc.PutUnsigned1(NewContextTag(1), 2)
	if err := enc.EndContainer(); err != nil { // end inner structure #2
		t.Fatal(err)
	}
	if err := enc.EndContainer(); err != nil { // end list
		t.Fatal(err)
	}
	enc.PutUnsigned1(NewContextTag(3), 0xBB)
	if err := enc.EndContainer(); err != nil { // end outer structure
		t.Fatal(err)
	}

	dec := NewDecoderWithBytes(enc.Bytes())

	type step struct {
		wantType ElementType
		wantCtx  int // -1 for anonymous/no context tag check
	}
	want := []step{
		{Structure, -1},      // outer structure begin
		{UnsignedInt1, 1},    // tag 1
		{List, 2},            // list begin (tag 2)
		{Structure, -1},      // list element 1 begin
		{UnsignedInt1, 1},    // element 1 field
		{EndOfContainer, -1}, // element 1 end
		{Structure, -1},      // list element 2 begin
		{UnsignedInt1, 1},    // element 2 field
		{EndOfContainer, -1}, // element 2 end
		{EndOfContainer, -1}, // list end
		{UnsignedInt1, 3},    // tag 3
		{EndOfContainer, -1}, // outer structure end
	}

	for i, w := range want {
		if !dec.Next() {
			t.Fatalf("step %d: Next() returned false, err=%v", i, dec.Error())
		}
		elem := dec.Element()
		if elem.Type() != w.wantType {
			t.Fatalf("step %d: got type %v, want %v", i, elem.Type(), w.wantType)
		}
		if w.wantCtx >= 0 {
			ct, ok := elem.Tag().(ContextTag)
			if !ok || int(ct.ContextNumber()) != w.wantCtx {
				t.Fatalf("step %d: got tag %v, want context tag %d", i, elem.Tag(), w.wantCtx)
			}
		}
	}
	if dec.Next() {
		t.Fatalf("expected no more elements, got %v", dec.Element())
	}
	if err := dec.Error(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func FuzzDecodeEdgeCases(f *testing.F) {
	// Invalid length (empty, 1 byte, max length)
	f.Add([]byte{})
	f.Add([]byte{0xFF})
	f.Add(make([]byte, 1024))

	// Invalid tag and type
	f.Add([]byte{0xFF, 0x00, 0x01, 0x02})

	// Random data
	for i := range 10 {
		buf := make([]byte, i*10)
		for j := range buf {
			buf[j] = byte(j * i)
		}
		f.Add(buf)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dec := NewDecoderWithBytes(data)
		for dec.More() && dec.Next() {
			_ = dec.Element()
		}
		_ = dec.Error() // Should not panic even if error occurs
	})
}
