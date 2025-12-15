package payload

import (
	"errors"
	"strconv"
	"strings"
)

// Manual code constants
const (
	// Code lengths (without check digit)
	manualCodeShortLength = 10 // 11 with check digit
	manualCodeLongLength  = 20 // 21 with check digit

	// Chunk lengths
	chunk1Length    = 1
	chunk2Length    = 5
	chunk3Length    = 4
	vendorIDLength  = 5
	productIDLength = 5

	// Maximum values for each chunk
	chunk1Max    = 7     // 3 bits (values 0-7; 8-9 reserved for future)
	chunk2Max    = 65535 // 16 bits (fits in 5 decimal digits: 00000-99999)
	chunk3Max    = 8191  // 13 bits (fits in 4 decimal digits: 0000-9999)
	vendorIDMax  = 65535 // 16 bits, but only 5 decimal digits (max 99999)
	productIDMax = 65535
)

// Bit positions within chunks (from spec)
const (
	// Chunk 1 (value 0-7):
	//   Bits 0-1: Discriminator MSBs (2 bits)
	//   Bit 2: VID/PID present flag
	chunk1DiscMSBsPos    = 0
	chunk1DiscMSBsLen    = 2
	chunk1VIDPIDFlagPos  = 2

	// Chunk 2 (value 0-65535):
	//   Bits 0-13: Passcode LSBs (14 bits)
	//   Bits 14-15: Discriminator LSBs (2 bits)
	chunk2PasscodeLSBsPos   = 0
	chunk2PasscodeLSBsLen   = 14
	chunk2DiscLSBsPos       = 14
	chunk2DiscLSBsLen       = 2

	// Chunk 3 (value 0-8191):
	//   Bits 0-12: Passcode MSBs (13 bits)
	chunk3PasscodeMSBsPos   = 0
	chunk3PasscodeMSBsLen   = 13
)

// Manual code errors
var (
	ErrManualCodeInvalidLength    = errors.New("manualcode: invalid length")
	ErrManualCodeInvalidChecksum  = errors.New("manualcode: invalid check digit")
	ErrManualCodeInvalidDigit     = errors.New("manualcode: invalid digit character")
	ErrManualCodeInvalidChunk1    = errors.New("manualcode: chunk1 value 8-9 reserved")
	ErrManualCodeInvalidVendorID  = errors.New("manualcode: vendor ID exceeds 16 bits")
	ErrManualCodeInvalidProductID = errors.New("manualcode: product ID exceeds 16 bits")
)

// ParseManualCode decodes a manual pairing code into a SetupPayload.
//
// The manual code is either 11 digits (short) or 21 digits (long):
//   - Short (11): discriminator + passcode + check digit
//   - Long (21): discriminator + passcode + VID + PID + check digit
//
// Input may contain formatting (dashes, spaces) which will be stripped.
func ParseManualCode(code string) (*SetupPayload, error) {
	// Strip formatting
	code = StripFormatting(code)

	// Validate check digit
	if !VerhoeffValidate(code) {
		return nil, ErrManualCodeInvalidChecksum
	}

	// Remove check digit for parsing
	codeWithoutCheck := code[:len(code)-1]

	// Check length
	isLongCode := false
	switch len(codeWithoutCheck) {
	case manualCodeShortLength:
		isLongCode = false
	case manualCodeLongLength:
		isLongCode = true
	default:
		return nil, ErrManualCodeInvalidLength
	}

	// Parse chunks
	pos := 0

	chunk1, err := parseDigits(codeWithoutCheck, &pos, chunk1Length)
	if err != nil {
		return nil, err
	}

	// Values 8-9 in chunk1 are reserved for future versions
	if chunk1 >= 8 {
		return nil, ErrManualCodeInvalidChunk1
	}

	// Check if VID/PID flag matches actual code length
	hasVIDPID := (chunk1 >> chunk1VIDPIDFlagPos) & 1
	if (hasVIDPID == 1) != isLongCode {
		return nil, ErrManualCodeInvalidLength
	}

	chunk2, err := parseDigits(codeWithoutCheck, &pos, chunk2Length)
	if err != nil {
		return nil, err
	}

	chunk3, err := parseDigits(codeWithoutCheck, &pos, chunk3Length)
	if err != nil {
		return nil, err
	}

	// Extract discriminator (4-bit short discriminator)
	// MSBs from chunk1, LSBs from chunk2
	discMSBs := (chunk1 >> chunk1DiscMSBsPos) & ((1 << chunk1DiscMSBsLen) - 1)
	discLSBs := (chunk2 >> chunk2DiscLSBsPos) & ((1 << chunk2DiscLSBsLen) - 1)
	discriminator := (discMSBs << chunk2DiscLSBsLen) | discLSBs

	// Extract passcode (27 bits)
	// LSBs from chunk2, MSBs from chunk3
	passcodeLSBs := (chunk2 >> chunk2PasscodeLSBsPos) & ((1 << chunk2PasscodeLSBsLen) - 1)
	passcodeMSBs := (chunk3 >> chunk3PasscodeMSBsPos) & ((1 << chunk3PasscodeMSBsLen) - 1)
	passcode := (passcodeMSBs << chunk2PasscodeLSBsLen) | passcodeLSBs

	// Validate passcode
	if passcode == 0 {
		return nil, ErrInvalidPasscode
	}

	payload := &SetupPayload{
		Discriminator: NewShortDiscriminator(uint8(discriminator)),
		Passcode:      passcode,
	}

	// Parse VID/PID for long codes
	if isLongCode {
		vendorID, err := parseDigits(codeWithoutCheck, &pos, vendorIDLength)
		if err != nil {
			return nil, err
		}
		if vendorID > vendorIDMax {
			return nil, ErrManualCodeInvalidVendorID
		}

		productID, err := parseDigits(codeWithoutCheck, &pos, productIDLength)
		if err != nil {
			return nil, err
		}
		if productID > productIDMax {
			return nil, ErrManualCodeInvalidProductID
		}

		payload.VendorID = uint16(vendorID)
		payload.ProductID = uint16(productID)
		payload.CommissioningFlow = CommissioningFlowCustom
	} else {
		payload.CommissioningFlow = CommissioningFlowStandard
	}

	return payload, nil
}

// EncodeManualCode encodes a SetupPayload to a manual pairing code.
//
// Returns a 21-digit code if CommissioningFlow is Custom, else 11-digit code.
func EncodeManualCode(payload *SetupPayload) (string, error) {
	if !payload.IsValidManualCode(ValidationModeProduce) {
		return "", errors.New("manualcode: invalid payload")
	}

	// Get short discriminator (4 bits)
	discriminator := uint32(payload.Discriminator.Short())

	// Get passcode
	passcode := payload.Passcode

	// Determine if we need long code (with VID/PID)
	isLongCode := payload.CommissioningFlow == CommissioningFlowCustom

	// Build chunk 1
	discMSBs := (discriminator >> chunk2DiscLSBsLen) & ((1 << chunk1DiscMSBsLen) - 1)
	vidPidFlag := uint32(0)
	if isLongCode {
		vidPidFlag = 1
	}
	chunk1 := (discMSBs << chunk1DiscMSBsPos) | (vidPidFlag << chunk1VIDPIDFlagPos)

	// Build chunk 2
	discLSBs := discriminator & ((1 << chunk2DiscLSBsLen) - 1)
	passcodeLSBs := passcode & ((1 << chunk2PasscodeLSBsLen) - 1)
	chunk2 := (passcodeLSBs << chunk2PasscodeLSBsPos) | (discLSBs << chunk2DiscLSBsPos)

	// Build chunk 3
	passcodeMSBs := (passcode >> chunk2PasscodeLSBsLen) & ((1 << chunk3PasscodeMSBsLen) - 1)
	chunk3 := passcodeMSBs << chunk3PasscodeMSBsPos

	// Format the code
	var sb strings.Builder
	sb.WriteString(strconv.FormatUint(uint64(chunk1), 10))
	sb.WriteString(padLeft(strconv.FormatUint(uint64(chunk2), 10), chunk2Length))
	sb.WriteString(padLeft(strconv.FormatUint(uint64(chunk3), 10), chunk3Length))

	if isLongCode {
		sb.WriteString(padLeft(strconv.FormatUint(uint64(payload.VendorID), 10), vendorIDLength))
		sb.WriteString(padLeft(strconv.FormatUint(uint64(payload.ProductID), 10), productIDLength))
	}

	// Add Verhoeff check digit
	checkDigit, err := VerhoeffCompute(sb.String())
	if err != nil {
		return "", err
	}
	sb.WriteByte(checkDigit)

	return sb.String(), nil
}

// StripFormatting removes dashes, spaces, and other formatting from a manual code.
func StripFormatting(code string) string {
	var sb strings.Builder
	sb.Grow(len(code))
	for _, c := range code {
		if c >= '0' && c <= '9' {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

// parseDigits parses n decimal digits from code starting at *pos.
func parseDigits(code string, pos *int, n int) (uint32, error) {
	if *pos+n > len(code) {
		return 0, ErrManualCodeInvalidLength
	}

	substr := code[*pos : *pos+n]
	*pos += n

	// Parse as decimal
	value, err := strconv.ParseUint(substr, 10, 32)
	if err != nil {
		return 0, ErrManualCodeInvalidDigit
	}

	return uint32(value), nil
}

// padLeft pads a string with leading zeros to reach the specified length.
func padLeft(s string, length int) string {
	if len(s) >= length {
		return s
	}
	return strings.Repeat("0", length-len(s)) + s
}
