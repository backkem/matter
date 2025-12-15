package payload

import "errors"

// Verhoeff implements the Verhoeff check digit algorithm for base-10 strings.
// This algorithm uses the dihedral group D_5 for error detection and can detect
// all single-digit errors and all adjacent transposition errors.
//
// See: https://en.wikipedia.org/wiki/Verhoeff_algorithm

// Verhoeff errors
var (
	ErrVerhoeffInvalidDigit = errors.New("verhoeff: invalid digit character")
	ErrVerhoeffEmptyString  = errors.New("verhoeff: empty string")
)

// verhoeffMultiply is the multiplication table for the dihedral group D_5.
// verhoeffMultiply[i][j] computes i ⊗ j in D_5.
var verhoeffMultiply = [10][10]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

// verhoeffPermute is the permutation table. Each digit is permuted based on its
// position in the string (iteration count).
var verhoeffPermute = [10]uint8{1, 5, 7, 6, 2, 8, 3, 0, 9, 4}

// verhoeffInverse is the inverse table for computing the check digit.
// verhoeffInverse[i] is the value j such that verhoeffMultiply[i][j] = 0.
var verhoeffInverse = [10]uint8{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}

// permute applies the permutation table iteratively.
// For position i (1-indexed from right), applies the permutation i times.
func permute(val int, iterations int) int {
	for i := 0; i < iterations; i++ {
		val = int(verhoeffPermute[val])
	}
	return val
}

// VerhoeffCompute computes the Verhoeff check digit for a string of digits.
// The input string should NOT include the check digit position.
// Returns the check digit character ('0'-'9').
func VerhoeffCompute(digits string) (byte, error) {
	if len(digits) == 0 {
		return 0, ErrVerhoeffEmptyString
	}

	c := 0 // Running checksum

	// Process digits from right to left (position 1 is rightmost)
	for i := len(digits) - 1; i >= 0; i-- {
		ch := digits[i]
		if ch < '0' || ch > '9' {
			return 0, ErrVerhoeffInvalidDigit
		}

		val := int(ch - '0')
		pos := len(digits) - i // 1-indexed position from right

		// Apply permutation based on position
		p := permute(val, pos)

		// Multiply into running checksum
		c = int(verhoeffMultiply[c][p])
	}

	// The check digit is the inverse of the checksum
	return '0' + verhoeffInverse[c], nil
}

// VerhoeffValidate validates that a string ends with a correct Verhoeff check digit.
// The input string should include the check digit as the last character.
// Returns true if the check digit is valid.
func VerhoeffValidate(digits string) bool {
	if len(digits) < 2 {
		return false
	}

	// Split into data and check digit
	data := digits[:len(digits)-1]
	checkDigit := digits[len(digits)-1]

	// Compute expected check digit
	expected, err := VerhoeffCompute(data)
	if err != nil {
		return false
	}

	return checkDigit == expected
}

// VerhoeffValidateCheckChar validates a check digit against a string.
// This is useful when the check digit is provided separately.
func VerhoeffValidateCheckChar(checkChar byte, digits string) bool {
	expected, err := VerhoeffCompute(digits)
	if err != nil {
		return false
	}
	return checkChar == expected
}
