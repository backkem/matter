// Package payload implements Matter onboarding payload parsing and generation.
// This includes QR code (Base38) and Manual Pairing Code formats.
package payload

import (
	"errors"
	"strings"
)

// Base38 encoding constants
const (
	// base38Alphabet is the character set for Base38 encoding (Table 59 in spec).
	// Order matters - the index is the numeric value.
	base38Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-."
	base38Radix    = 38
)

// base38CharsPerChunk defines the number of Base38 characters needed for each chunk size.
// Index 0: 1 byte needs 2 chars (max value 255 < 38^2 = 1444)
// Index 1: 2 bytes need 4 chars (max value 65535 < 38^4 = 2085136)
// Index 2: 3 bytes need 5 chars (max value 16777215 < 38^5 = 79235168)
var base38CharsPerChunk = [3]int{2, 4, 5}

// base38DecodeTable maps ASCII characters to their Base38 values.
// Characters are indexed by (ASCII value - '-'), where '-' is ASCII 45.
// Invalid characters are marked with -1.
var base38DecodeTable = [46]int8{
	36, // '-' (ASCII 45)
	37, // '.' (ASCII 46)
	-1, // '/' (ASCII 47) - invalid
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, // '0'-'9' (ASCII 48-57)
	-1, -1, -1, -1, -1, -1, -1, // ':'-'@' (ASCII 58-64) - invalid
	10, 11, 12, 13, 14, 15, 16, 17, 18, 19, // 'A'-'J' (ASCII 65-74)
	20, 21, 22, 23, 24, 25, 26, 27, 28, 29, // 'K'-'T' (ASCII 75-84)
	30, 31, 32, 33, 34, 35, // 'U'-'Z' (ASCII 85-90)
}

// Base38 encoding errors
var (
	ErrBase38InvalidChar   = errors.New("base38: invalid character")
	ErrBase38InvalidLength = errors.New("base38: invalid string length")
	ErrBase38Overflow      = errors.New("base38: encoded value too large for chunk")
)

// Base38Decode decodes a Base38-encoded string to bytes.
//
// The encoding uses chunks:
//   - 5 characters decode to 3 bytes
//   - 4 characters decode to 2 bytes (trailing)
//   - 2 characters decode to 1 byte (trailing)
//
// Characters are processed in reverse order within each chunk (least significant first).
func Base38Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}

	// Convert to uppercase for case-insensitive decoding
	s = strings.ToUpper(s)

	var result []byte
	remaining := len(s)
	pos := 0

	for remaining > 0 {
		var charsInChunk, bytesInChunk int

		switch {
		case remaining >= base38CharsPerChunk[2]:
			charsInChunk = base38CharsPerChunk[2] // 5 chars
			bytesInChunk = 3
		case remaining == base38CharsPerChunk[1]:
			charsInChunk = base38CharsPerChunk[1] // 4 chars
			bytesInChunk = 2
		case remaining == base38CharsPerChunk[0]:
			charsInChunk = base38CharsPerChunk[0] // 2 chars
			bytesInChunk = 1
		default:
			// Invalid length: not 5n, 5n+4, or 5n+2
			return nil, ErrBase38InvalidLength
		}

		// Decode chunk: process characters in reverse order (LSB first in string)
		var value uint32
		for i := charsInChunk - 1; i >= 0; i-- {
			c := s[pos+i]

			// Check character range
			if c < '-' || c > 'Z' {
				return nil, ErrBase38InvalidChar
			}

			// Look up value
			idx := c - '-'
			if int(idx) >= len(base38DecodeTable) {
				return nil, ErrBase38InvalidChar
			}

			v := base38DecodeTable[idx]
			if v < 0 {
				return nil, ErrBase38InvalidChar
			}

			value = value*base38Radix + uint32(v)
		}

		pos += charsInChunk
		remaining -= charsInChunk

		// Extract bytes from value (little-endian)
		for i := 0; i < bytesInChunk; i++ {
			result = append(result, byte(value&0xFF))
			value >>= 8
		}

		// Check for overflow
		if value > 0 {
			return nil, ErrBase38Overflow
		}
	}

	return result, nil
}

// Base38Encode encodes bytes to a Base38 string.
//
// The encoding uses chunks:
//   - 3 bytes encode to 5 characters
//   - 2 bytes encode to 4 characters (trailing)
//   - 1 byte encodes to 2 characters (trailing)
//
// Characters are emitted in reverse order within each chunk (least significant first).
func Base38Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	result := make([]byte, 0, Base38EncodedLength(len(data)))
	remaining := len(data)
	pos := 0

	for remaining > 0 {
		var bytesInChunk int
		if remaining >= 3 {
			bytesInChunk = 3
		} else {
			bytesInChunk = remaining
		}

		// Build value from bytes (little-endian)
		var value uint32
		for i := bytesInChunk - 1; i >= 0; i-- {
			value = (value << 8) | uint32(data[pos+i])
		}

		pos += bytesInChunk
		remaining -= bytesInChunk

		// Determine number of output characters
		charsNeeded := base38CharsPerChunk[bytesInChunk-1]

		// Extract Base38 digits (least significant first)
		for i := 0; i < charsNeeded; i++ {
			result = append(result, base38Alphabet[value%base38Radix])
			value /= base38Radix
		}
	}

	return string(result)
}

// Base38EncodedLength returns the number of characters needed to encode n bytes.
// Formula: (n/3)*5 + remainder, where remainder is 0, 2, or 4 for 0, 1, or 2 extra bytes.
func Base38EncodedLength(n int) int {
	fullChunks := n / 3
	extraBytes := n % 3

	length := fullChunks * 5
	if extraBytes > 0 {
		length += base38CharsPerChunk[extraBytes-1]
	}

	return length
}
