package casesession

import (
	"bytes"
	"testing"

	"github.com/backkem/matter/pkg/crypto"
)

// TestDeriveS2K verifies S2K derivation.
func TestDeriveS2K(t *testing.T) {
	// Create test inputs
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	var ipk [crypto.SymmetricKeySize]byte
	for i := range ipk {
		ipk[i] = byte(i + 100)
	}

	var responderRandom [RandomSize]byte
	for i := range responderRandom {
		responderRandom[i] = byte(i + 50)
	}

	var responderEphPubKey [crypto.P256PublicKeySizeBytes]byte
	responderEphPubKey[0] = 0x04
	for i := 1; i < len(responderEphPubKey); i++ {
		responderEphPubKey[i] = byte(i)
	}

	msg1Bytes := []byte{0x15, 0x01, 0x02, 0x03, 0x04, 0x05}

	// Derive key
	key, err := DeriveS2K(sharedSecret, ipk, responderRandom, responderEphPubKey, msg1Bytes)
	if err != nil {
		t.Fatalf("DeriveS2K failed: %v", err)
	}

	// Verify key is non-zero
	var zeroKey [crypto.SymmetricKeySize]byte
	if key == zeroKey {
		t.Error("DeriveS2K returned zero key")
	}

	// Verify determinism - same inputs should produce same key
	key2, err := DeriveS2K(sharedSecret, ipk, responderRandom, responderEphPubKey, msg1Bytes)
	if err != nil {
		t.Fatalf("second DeriveS2K failed: %v", err)
	}
	if key != key2 {
		t.Error("DeriveS2K is not deterministic")
	}

	// Verify different inputs produce different keys
	differentIPK := ipk
	differentIPK[0] ^= 0xFF
	key3, err := DeriveS2K(sharedSecret, differentIPK, responderRandom, responderEphPubKey, msg1Bytes)
	if err != nil {
		t.Fatalf("third DeriveS2K failed: %v", err)
	}
	if key == key3 {
		t.Error("different IPK should produce different key")
	}
}

// TestDeriveS3K verifies S3K derivation.
func TestDeriveS3K(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	var ipk [crypto.SymmetricKeySize]byte
	for i := range ipk {
		ipk[i] = byte(i + 100)
	}

	msg1Bytes := []byte{0x15, 0x01, 0x02, 0x03}
	msg2Bytes := []byte{0x15, 0x04, 0x05, 0x06}

	key, err := DeriveS3K(sharedSecret, ipk, msg1Bytes, msg2Bytes)
	if err != nil {
		t.Fatalf("DeriveS3K failed: %v", err)
	}

	var zeroKey [crypto.SymmetricKeySize]byte
	if key == zeroKey {
		t.Error("DeriveS3K returned zero key")
	}

	// Verify determinism
	key2, err := DeriveS3K(sharedSecret, ipk, msg1Bytes, msg2Bytes)
	if err != nil {
		t.Fatalf("second DeriveS3K failed: %v", err)
	}
	if key != key2 {
		t.Error("DeriveS3K is not deterministic")
	}
}

// TestDeriveS1RK verifies S1RK derivation.
func TestDeriveS1RK(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	var initiatorRandom [RandomSize]byte
	for i := range initiatorRandom {
		initiatorRandom[i] = byte(i + 10)
	}

	var resumptionID [ResumptionIDSize]byte
	for i := range resumptionID {
		resumptionID[i] = byte(i + 200)
	}

	key, err := DeriveS1RK(sharedSecret, initiatorRandom, resumptionID)
	if err != nil {
		t.Fatalf("DeriveS1RK failed: %v", err)
	}

	var zeroKey [crypto.SymmetricKeySize]byte
	if key == zeroKey {
		t.Error("DeriveS1RK returned zero key")
	}
}

// TestDeriveS2RK verifies S2RK derivation.
func TestDeriveS2RK(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	var initiatorRandom [RandomSize]byte
	for i := range initiatorRandom {
		initiatorRandom[i] = byte(i + 10)
	}

	var newResumptionID [ResumptionIDSize]byte
	for i := range newResumptionID {
		newResumptionID[i] = byte(i + 150)
	}

	key, err := DeriveS2RK(sharedSecret, initiatorRandom, newResumptionID)
	if err != nil {
		t.Fatalf("DeriveS2RK failed: %v", err)
	}

	var zeroKey [crypto.SymmetricKeySize]byte
	if key == zeroKey {
		t.Error("DeriveS2RK returned zero key")
	}

	// S1RK and S2RK with same inputs but different info strings should be different
	key1RK, err := DeriveS1RK(sharedSecret, initiatorRandom, newResumptionID)
	if err != nil {
		t.Fatalf("DeriveS1RK failed: %v", err)
	}
	if key == key1RK {
		t.Error("S2RK and S1RK should be different")
	}
}

// TestDeriveSessionKeys verifies session key derivation.
func TestDeriveSessionKeys(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	var ipk [crypto.SymmetricKeySize]byte
	for i := range ipk {
		ipk[i] = byte(i + 100)
	}

	msg1Bytes := []byte{0x15, 0x01, 0x02}
	msg2Bytes := []byte{0x15, 0x03, 0x04}
	msg3Bytes := []byte{0x15, 0x05, 0x06}

	keys, err := DeriveSessionKeys(sharedSecret, ipk, msg1Bytes, msg2Bytes, msg3Bytes)
	if err != nil {
		t.Fatalf("DeriveSessionKeys failed: %v", err)
	}

	var zeroKey [SessionKeySize]byte
	if keys.I2RKey == zeroKey {
		t.Error("I2RKey is zero")
	}
	if keys.R2IKey == zeroKey {
		t.Error("R2IKey is zero")
	}
	if keys.AttestationChallenge == zeroKey {
		t.Error("AttestationChallenge is zero")
	}

	// All three keys should be different
	if keys.I2RKey == keys.R2IKey {
		t.Error("I2RKey and R2IKey should be different")
	}
	if keys.I2RKey == keys.AttestationChallenge {
		t.Error("I2RKey and AttestationChallenge should be different")
	}
	if keys.R2IKey == keys.AttestationChallenge {
		t.Error("R2IKey and AttestationChallenge should be different")
	}
}

// TestDeriveResumptionSessionKeys verifies resumption session key derivation.
func TestDeriveResumptionSessionKeys(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	var ipk [crypto.SymmetricKeySize]byte
	for i := range ipk {
		ipk[i] = byte(i + 100)
	}

	msg1Bytes := []byte{0x15, 0x01, 0x02}
	sigma2ResumeBytes := []byte{0x15, 0x03, 0x04}

	keys, err := DeriveResumptionSessionKeys(sharedSecret, ipk, msg1Bytes, sigma2ResumeBytes)
	if err != nil {
		t.Fatalf("DeriveResumptionSessionKeys failed: %v", err)
	}

	var zeroKey [SessionKeySize]byte
	if keys.I2RKey == zeroKey {
		t.Error("I2RKey is zero")
	}
	if keys.R2IKey == zeroKey {
		t.Error("R2IKey is zero")
	}

	// Verify determinism
	keys2, err := DeriveResumptionSessionKeys(sharedSecret, ipk, msg1Bytes, sigma2ResumeBytes)
	if err != nil {
		t.Fatalf("second DeriveResumptionSessionKeys failed: %v", err)
	}
	if keys.I2RKey != keys2.I2RKey {
		t.Error("DeriveResumptionSessionKeys is not deterministic")
	}

	// Resumption keys should be different from full handshake keys with actual msg3
	msg2Bytes := []byte{0x15, 0x05, 0x06}
	msg3Bytes := []byte{0x15, 0x07, 0x08}
	fullKeys, err := DeriveSessionKeys(sharedSecret, ipk, msg1Bytes, msg2Bytes, msg3Bytes)
	if err != nil {
		t.Fatalf("DeriveSessionKeys failed: %v", err)
	}
	if keys.I2RKey == fullKeys.I2RKey {
		t.Error("resumption and full handshake keys should differ")
	}
}

// TestEncryptDecryptTBEData verifies TBE data encryption/decryption roundtrip.
func TestEncryptDecryptTBEData(t *testing.T) {
	var key [crypto.SymmetricKeySize]byte
	for i := range key {
		key[i] = byte(i + 50)
	}

	plaintext := []byte("This is the TBE data to encrypt for CASE protocol testing.")

	// Test with Sigma2 nonce
	ciphertext, err := EncryptTBEData(key, plaintext, Sigma2Nonce, nil)
	if err != nil {
		t.Fatalf("EncryptTBEData failed: %v", err)
	}

	// Ciphertext should be plaintext length + MIC size
	expectedLen := len(plaintext) + MICSize
	if len(ciphertext) != expectedLen {
		t.Errorf("ciphertext length: got %d, want %d", len(ciphertext), expectedLen)
	}

	// Decrypt
	decrypted, err := DecryptTBEData(key, ciphertext, Sigma2Nonce, nil)
	if err != nil {
		t.Fatalf("DecryptTBEData failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted data mismatch")
	}

	// Test with Sigma3 nonce
	ciphertext3, err := EncryptTBEData(key, plaintext, Sigma3Nonce, nil)
	if err != nil {
		t.Fatalf("EncryptTBEData with Sigma3Nonce failed: %v", err)
	}

	decrypted3, err := DecryptTBEData(key, ciphertext3, Sigma3Nonce, nil)
	if err != nil {
		t.Fatalf("DecryptTBEData with Sigma3Nonce failed: %v", err)
	}

	if !bytes.Equal(decrypted3, plaintext) {
		t.Errorf("decrypted data mismatch for Sigma3")
	}

	// Different nonces should produce different ciphertexts
	if bytes.Equal(ciphertext, ciphertext3) {
		t.Error("different nonces should produce different ciphertexts")
	}
}

// TestEncryptDecryptTBEData_WrongKey verifies decryption fails with wrong key.
func TestEncryptDecryptTBEData_WrongKey(t *testing.T) {
	var key [crypto.SymmetricKeySize]byte
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("Secret data")

	ciphertext, err := EncryptTBEData(key, plaintext, Sigma2Nonce, nil)
	if err != nil {
		t.Fatalf("EncryptTBEData failed: %v", err)
	}

	// Try to decrypt with wrong key
	wrongKey := key
	wrongKey[0] ^= 0xFF

	_, err = DecryptTBEData(wrongKey, ciphertext, Sigma2Nonce, nil)
	if err == nil {
		t.Error("expected decryption to fail with wrong key")
	}
}

// TestEncryptDecryptTBEData_WrongNonce verifies decryption fails with wrong nonce.
func TestEncryptDecryptTBEData_WrongNonce(t *testing.T) {
	var key [crypto.SymmetricKeySize]byte
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("Secret data")

	ciphertext, err := EncryptTBEData(key, plaintext, Sigma2Nonce, nil)
	if err != nil {
		t.Fatalf("EncryptTBEData failed: %v", err)
	}

	// Try to decrypt with wrong nonce
	_, err = DecryptTBEData(key, ciphertext, Sigma3Nonce, nil)
	if err == nil {
		t.Error("expected decryption to fail with wrong nonce")
	}
}

// TestComputeVerifyResumeMIC verifies resume MIC computation and verification.
func TestComputeVerifyResumeMIC(t *testing.T) {
	var key [crypto.SymmetricKeySize]byte
	for i := range key {
		key[i] = byte(i + 30)
	}

	// Compute MIC with Resume1 nonce
	mic, err := ComputeResumeMIC(key, Resume1Nonce)
	if err != nil {
		t.Fatalf("ComputeResumeMIC failed: %v", err)
	}

	// Verify correct MIC
	if !VerifyResumeMIC(key, Resume1Nonce, mic) {
		t.Error("VerifyResumeMIC should return true for correct MIC")
	}

	// Verify wrong MIC fails
	wrongMIC := mic
	wrongMIC[0] ^= 0xFF
	if VerifyResumeMIC(key, Resume1Nonce, wrongMIC) {
		t.Error("VerifyResumeMIC should return false for wrong MIC")
	}

	// Verify wrong key fails
	wrongKey := key
	wrongKey[0] ^= 0xFF
	if VerifyResumeMIC(wrongKey, Resume1Nonce, mic) {
		t.Error("VerifyResumeMIC should return false for wrong key")
	}

	// Verify wrong nonce fails
	if VerifyResumeMIC(key, Resume2Nonce, mic) {
		t.Error("VerifyResumeMIC should return false for wrong nonce")
	}

	// Test Resume2 nonce
	mic2, err := ComputeResumeMIC(key, Resume2Nonce)
	if err != nil {
		t.Fatalf("ComputeResumeMIC with Resume2Nonce failed: %v", err)
	}

	if !VerifyResumeMIC(key, Resume2Nonce, mic2) {
		t.Error("VerifyResumeMIC should return true for Resume2 MIC")
	}

	// Different nonces should produce different MICs
	if mic == mic2 {
		t.Error("different nonces should produce different MICs")
	}
}

// TestKeyDifferentiation verifies that different key types are distinct.
func TestKeyDifferentiation(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	var ipk [crypto.SymmetricKeySize]byte
	for i := range ipk {
		ipk[i] = byte(i + 100)
	}

	var random [RandomSize]byte
	for i := range random {
		random[i] = byte(i + 50)
	}

	var ephPubKey [crypto.P256PublicKeySizeBytes]byte
	ephPubKey[0] = 0x04

	var resumptionID [ResumptionIDSize]byte
	for i := range resumptionID {
		resumptionID[i] = byte(i + 200)
	}

	msg1 := []byte{0x15, 0x01}
	msg2 := []byte{0x15, 0x02}
	msg3 := []byte{0x15, 0x03}

	s2k, err := DeriveS2K(sharedSecret, ipk, random, ephPubKey, msg1)
	if err != nil {
		t.Fatalf("DeriveS2K failed: %v", err)
	}

	s3k, err := DeriveS3K(sharedSecret, ipk, msg1, msg2)
	if err != nil {
		t.Fatalf("DeriveS3K failed: %v", err)
	}

	s1rk, err := DeriveS1RK(sharedSecret, random, resumptionID)
	if err != nil {
		t.Fatalf("DeriveS1RK failed: %v", err)
	}

	s2rk, err := DeriveS2RK(sharedSecret, random, resumptionID)
	if err != nil {
		t.Fatalf("DeriveS2RK failed: %v", err)
	}

	sessionKeys, err := DeriveSessionKeys(sharedSecret, ipk, msg1, msg2, msg3)
	if err != nil {
		t.Fatalf("DeriveSessionKeys failed: %v", err)
	}

	// All keys should be different
	keys := [][]byte{
		s2k[:],
		s3k[:],
		s1rk[:],
		s2rk[:],
		sessionKeys.I2RKey[:],
		sessionKeys.R2IKey[:],
		sessionKeys.AttestationChallenge[:],
	}

	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if bytes.Equal(keys[i], keys[j]) {
				t.Errorf("keys[%d] and keys[%d] should be different", i, j)
			}
		}
	}
}
