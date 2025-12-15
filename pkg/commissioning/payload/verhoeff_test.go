package payload

import "testing"

func TestVerhoeffCompute(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    byte
		wantErr error
	}{
		// Test vectors from C++ TestVerhoeff.cpp
		{name: "cpp vector 236", input: "236", want: '3'},
		{name: "cpp vector 0", input: "0", want: '4'},
		{name: "cpp vector 11111", input: "11111", want: '5'},

		// Long numbers from C++ tests
		{name: "cpp long 1", input: "4356678912349008", want: '7'},
		{name: "cpp long 2", input: "78324562830019274123748", want: '4'},

		// Derived from C++ ValidateCheckChar tests (string with check digit removed)
		// ValidateCheckChar("123451") valid → ComputeCheckChar("12345") = '1'
		{name: "cpp derived 12345", input: "12345", want: '1'},
		// ValidateCheckChar("0987652") valid → ComputeCheckChar("098765") = '2'
		{name: "cpp derived 098765", input: "098765", want: '2'},
		// ValidateCheckChar("150") valid → ComputeCheckChar("15") = '0'
		{name: "cpp derived 15", input: "15", want: '0'},

		// Error cases
		// Note: C++ returns '0' for empty string; we return an error for safety
		{name: "empty string", input: "", wantErr: ErrVerhoeffEmptyString},
		{name: "invalid char F", input: "123F4567", wantErr: ErrVerhoeffInvalidDigit},
		{name: "invalid char A", input: "0A", wantErr: ErrVerhoeffInvalidDigit},
		{name: "invalid char I", input: "I", wantErr: ErrVerhoeffInvalidDigit},
		{name: "invalid char dot", input: "23.4", wantErr: ErrVerhoeffInvalidDigit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerhoeffCompute(tt.input)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("VerhoeffCompute(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("VerhoeffCompute(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("VerhoeffCompute(%q) = %q, want %q", tt.input, string(got), string(tt.want))
			}
		})
	}
}

func TestVerhoeffValidate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Valid cases from C++ TestVerhoeff.cpp
		{name: "cpp valid 123451", input: "123451", want: true},
		{name: "cpp valid 0987652", input: "0987652", want: true},
		{name: "cpp valid 150", input: "150", want: true},

		// Derived from ComputeCheckChar tests
		{name: "valid 2363", input: "2363", want: true}, // 236 → 3
		{name: "valid 04", input: "04", want: true},     // 0 → 4
		{name: "valid 111115", input: "111115", want: true}, // 11111 → 5

		// Long numbers from C++
		{name: "valid long 1", input: "43566789123490087", want: true},
		{name: "valid long 2", input: "783245628300192741237484", want: true},

		// Invalid cases from C++ tests
		{name: "cpp invalid 123456", input: "123456", want: false},
		{name: "cpp invalid 0987651", input: "0987651", want: false},
		{name: "cpp invalid 157", input: "157", want: false},

		// Invalid: transposition (check digit would be different)
		{name: "transposition", input: "3263", want: false}, // 2363 with 2 and 3 swapped

		// Edge cases
		{name: "too short", input: "0", want: false},
		{name: "empty", input: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerhoeffValidate(tt.input)
			if got != tt.want {
				t.Errorf("VerhoeffValidate(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestVerhoeffValidateCheckChar(t *testing.T) {
	tests := []struct {
		name      string
		checkChar byte
		digits    string
		want      bool
	}{
		{name: "valid 236", checkChar: '3', digits: "236", want: true},
		{name: "invalid 236", checkChar: '4', digits: "236", want: false},
		{name: "valid single 0", checkChar: '4', digits: "0", want: true},
		{name: "invalid single 0", checkChar: '5', digits: "0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VerhoeffValidateCheckChar(tt.checkChar, tt.digits)
			if got != tt.want {
				t.Errorf("VerhoeffValidateCheckChar(%q, %q) = %v, want %v",
					string(tt.checkChar), tt.digits, got, tt.want)
			}
		})
	}
}

// TestVerhoeffErrorDetection tests that the algorithm detects various types of errors.
func TestVerhoeffErrorDetection(t *testing.T) {
	// Start with a valid string
	valid := "2363" // 236 with check digit 3

	// Single digit substitution should be detected
	t.Run("single digit error", func(t *testing.T) {
		for pos := 0; pos < len(valid)-1; pos++ { // Don't modify check digit
			for digit := byte('0'); digit <= byte('9'); digit++ {
				if digit == valid[pos] {
					continue
				}
				modified := []byte(valid)
				modified[pos] = digit
				if VerhoeffValidate(string(modified)) {
					t.Errorf("Failed to detect single digit error at position %d: %s", pos, string(modified))
				}
			}
		}
	})

	// Adjacent transposition should be detected
	t.Run("adjacent transposition", func(t *testing.T) {
		for pos := 0; pos < len(valid)-2; pos++ { // Don't swap with check digit
			if valid[pos] == valid[pos+1] {
				continue // Same digits, transposition has no effect
			}
			modified := []byte(valid)
			modified[pos], modified[pos+1] = modified[pos+1], modified[pos]
			if VerhoeffValidate(string(modified)) {
				t.Errorf("Failed to detect adjacent transposition at position %d: %s", pos, string(modified))
			}
		}
	})
}
