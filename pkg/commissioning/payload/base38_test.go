package payload

import (
	"bytes"
	"testing"
)

func TestBase38Decode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr error
	}{
		// Empty
		{name: "empty", input: "", want: []byte{}},

		// Single byte (2 chars)
		{name: "single byte 10", input: "A0", want: []byte{10}},
		{name: "single byte 35", input: "Z0", want: []byte{35}},
		{name: "single byte 255", input: "R6", want: []byte{255}},

		// Two bytes (4 chars)
		{name: "two bytes", input: "OT10", want: []byte{10, 10}},
		{name: "two bytes max", input: "NE71", want: []byte{255, 255}},
		{name: "two bytes 256", input: "S600", want: []byte{0, 1}},

		// Three bytes (5 chars)
		{name: "three bytes", input: "-N.B0", want: []byte{10, 10, 10}},
		{name: "three bytes max", input: "PLS18", want: []byte{255, 255, 255}},
		{name: "three bytes zeros", input: "OT100", want: []byte{10, 10, 0}},
		{name: "three bytes 65536", input: "OE710", want: []byte{0, 0, 1}},

		// String encoding
		{name: "Hello World!", input: "KKHF3W2S013OPM3EJX11", want: []byte("Hello World!")},

		// Case insensitive
		{name: "lowercase", input: "a0", want: []byte{10}},
		{name: "mixed case", input: "kKhF3w2S013oPm3EjX11", want: []byte("Hello World!")},

		// Errors
		{name: "invalid char space", input: " 0", wantErr: ErrBase38InvalidChar},
		{name: "invalid char exclaim", input: "!0", wantErr: ErrBase38InvalidChar},
		{name: "invalid char slash", input: "/0", wantErr: ErrBase38InvalidChar},
		{name: "invalid char colon", input: ":0", wantErr: ErrBase38InvalidChar},
		{name: "invalid char at", input: "@0", wantErr: ErrBase38InvalidChar},
		{name: "invalid char bracket", input: "[0", wantErr: ErrBase38InvalidChar},

		// Invalid lengths (not 2, 4, 5, 7, 9, 10, ...)
		// Valid lengths are 5n, 5n+2, 5n+4 (for n>=0)
		{name: "invalid length 1", input: "A", wantErr: ErrBase38InvalidLength},
		{name: "invalid length 3", input: "ABC", wantErr: ErrBase38InvalidLength},
		{name: "invalid length 6", input: "000000", wantErr: ErrBase38InvalidLength}, // 5+1 chars
		{name: "invalid length 8", input: "00000000", wantErr: ErrBase38InvalidLength}, // 5+3 chars

		// Overflow: value too large for chunk
		{name: "overflow 1 byte", input: "S6", wantErr: ErrBase38Overflow},       // 256 in 1 byte
		{name: "overflow 2 bytes", input: "OE71", wantErr: ErrBase38Overflow},    // 65536 in 2 bytes
		{name: "overflow 3 bytes", input: "QLS18", wantErr: ErrBase38Overflow},   // 16777216 in 3 bytes
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Base38Decode(tt.input)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Base38Decode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("Base38Decode(%q) unexpected error: %v", tt.input, err)
				return
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Base38Decode(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBase38Encode(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		// Empty
		{name: "empty", input: []byte{}, want: ""},

		// Single byte (2 chars)
		{name: "single byte 10", input: []byte{10}, want: "A0"},
		{name: "single byte 35", input: []byte{35}, want: "Z0"},
		{name: "single byte 255", input: []byte{255}, want: "R6"},

		// Two bytes (4 chars)
		{name: "two bytes", input: []byte{10, 10}, want: "OT10"},
		{name: "two bytes max", input: []byte{255, 255}, want: "NE71"},
		{name: "two bytes 255,0", input: []byte{255, 0}, want: "R600"},

		// Three bytes (5 chars)
		{name: "three bytes", input: []byte{10, 10, 10}, want: "-N.B0"},
		{name: "three bytes max", input: []byte{255, 255, 255}, want: "PLS18"},
		{name: "three bytes 46,0,0", input: []byte{46, 0, 0}, want: "81000"},

		// String encoding
		{name: "Hello World!", input: []byte("Hello World!"), want: "KKHF3W2S013OPM3EJX11"},

		// Various patterns
		{name: "three bytes 10,10,0", input: []byte{10, 10, 0}, want: "OT100"},
		{name: "three bytes 10,10,40", input: []byte{10, 10, 40}, want: "Y6V91"},
		{name: "three bytes 10,10,41", input: []byte{10, 10, 41}, want: "KL0B1"},
		{name: "three bytes 10,10,255", input: []byte{10, 10, 255}, want: "Q-M08"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Base38Encode(tt.input)
			if got != tt.want {
				t.Errorf("Base38Encode(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBase38Roundtrip(t *testing.T) {
	tests := [][]byte{
		{},
		{0},
		{255},
		{0, 0},
		{255, 255},
		{0, 0, 0},
		{255, 255, 255},
		{1, 2, 3, 4, 5},
		[]byte("Hello World!"),
		[]byte("Matter QR Code Test"),
	}

	for _, input := range tests {
		encoded := Base38Encode(input)
		decoded, err := Base38Decode(encoded)
		if err != nil {
			t.Errorf("Roundtrip failed for %v: encode=%q, decode error=%v", input, encoded, err)
			continue
		}
		if !bytes.Equal(decoded, input) {
			t.Errorf("Roundtrip failed for %v: encode=%q, decode=%v", input, encoded, decoded)
		}
	}
}

func TestBase38EncodedLength(t *testing.T) {
	tests := []struct {
		n    int
		want int
	}{
		{0, 0},
		{1, 2},
		{2, 4},
		{3, 5},
		{4, 7},
		{5, 9},
		{6, 10},
		{12, 20}, // "Hello World!" = 12 bytes = 20 chars
	}

	for _, tt := range tests {
		got := Base38EncodedLength(tt.n)
		if got != tt.want {
			t.Errorf("Base38EncodedLength(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}
