package tlv

import (
	"testing"
)

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
