package casesession

import (
	"github.com/backkem/matter/pkg/crypto"
)

// DeriveS2K derives the Sigma2 encryption key.
//
// S2K = HKDF-SHA256(
//
//	inputKey = SharedSecret,
//	salt = IPK || ResponderRandom || ResponderEphPubKey || TranscriptHash(Msg1),
//	info = "Sigma2",
//	len = 16
//
// )
//
// Parameters:
//   - sharedSecret: ECDH shared secret (32 bytes)
//   - ipk: Identity Protection Key (16 bytes)
//   - responderRandom: 32-byte random from Sigma2
//   - responderEphPubKey: 65-byte responder ephemeral public key
//   - msg1Bytes: Raw TLV bytes of Sigma1 message
//
// Returns the 16-byte S2K key for encrypting TBEData2.
func DeriveS2K(
	sharedSecret []byte,
	ipk [crypto.SymmetricKeySize]byte,
	responderRandom [RandomSize]byte,
	responderEphPubKey [crypto.P256PublicKeySizeBytes]byte,
	msg1Bytes []byte,
) ([crypto.SymmetricKeySize]byte, error) {
	var result [crypto.SymmetricKeySize]byte

	// TranscriptHash = SHA256(Msg1)
	transcriptHash := crypto.SHA256(msg1Bytes)

	// Salt = IPK || ResponderRandom || ResponderEphPubKey || TranscriptHash
	salt := make([]byte, 0, crypto.SymmetricKeySize+RandomSize+crypto.P256PublicKeySizeBytes+crypto.SHA256LenBytes)
	salt = append(salt, ipk[:]...)
	salt = append(salt, responderRandom[:]...)
	salt = append(salt, responderEphPubKey[:]...)
	salt = append(salt, transcriptHash[:]...)

	// Derive key
	key, err := crypto.HKDFSHA256(sharedSecret, salt, S2KInfo, crypto.SymmetricKeySize)
	if err != nil {
		return result, err
	}

	copy(result[:], key)
	return result, nil
}

// DeriveS3K derives the Sigma3 encryption key.
//
// S3K = HKDF-SHA256(
//
//	inputKey = SharedSecret,
//	salt = IPK || TranscriptHash(Msg1 || Msg2),
//	info = "Sigma3",
//	len = 16
//
// )
//
// Parameters:
//   - sharedSecret: ECDH shared secret (32 bytes)
//   - ipk: Identity Protection Key (16 bytes)
//   - msg1Bytes: Raw TLV bytes of Sigma1 message
//   - msg2Bytes: Raw TLV bytes of Sigma2 message
//
// Returns the 16-byte S3K key for encrypting TBEData3.
func DeriveS3K(
	sharedSecret []byte,
	ipk [crypto.SymmetricKeySize]byte,
	msg1Bytes []byte,
	msg2Bytes []byte,
) ([crypto.SymmetricKeySize]byte, error) {
	var result [crypto.SymmetricKeySize]byte

	// TranscriptHash = SHA256(Msg1 || Msg2)
	transcript := append(msg1Bytes, msg2Bytes...)
	transcriptHash := crypto.SHA256(transcript)

	// Salt = IPK || TranscriptHash
	salt := make([]byte, 0, crypto.SymmetricKeySize+crypto.SHA256LenBytes)
	salt = append(salt, ipk[:]...)
	salt = append(salt, transcriptHash[:]...)

	// Derive key
	key, err := crypto.HKDFSHA256(sharedSecret, salt, S3KInfo, crypto.SymmetricKeySize)
	if err != nil {
		return result, err
	}

	copy(result[:], key)
	return result, nil
}

// DeriveS1RK derives the Sigma1 resumption key for verifying initiatorResumeMIC.
//
// S1RK = HKDF-SHA256(
//
//	inputKey = SharedSecret (from previous session),
//	salt = InitiatorRandom || ResumptionID (from previous session),
//	info = "Sigma1_Resume",
//	len = 16
//
// )
//
// Parameters:
//   - sharedSecret: ECDH shared secret from the previous session
//   - initiatorRandom: 32-byte random from current Sigma1
//   - resumptionID: 16-byte resumption ID from previous session
//
// Returns the 16-byte S1RK key for computing/verifying Resume1MIC.
func DeriveS1RK(
	sharedSecret []byte,
	initiatorRandom [RandomSize]byte,
	resumptionID [ResumptionIDSize]byte,
) ([crypto.SymmetricKeySize]byte, error) {
	var result [crypto.SymmetricKeySize]byte

	// Salt = InitiatorRandom || ResumptionID
	salt := make([]byte, 0, RandomSize+ResumptionIDSize)
	salt = append(salt, initiatorRandom[:]...)
	salt = append(salt, resumptionID[:]...)

	// Derive key
	key, err := crypto.HKDFSHA256(sharedSecret, salt, S1RKInfo, crypto.SymmetricKeySize)
	if err != nil {
		return result, err
	}

	copy(result[:], key)
	return result, nil
}

// DeriveS2RK derives the Sigma2 resumption key for computing Resume2MIC.
//
// S2RK = HKDF-SHA256(
//
//	inputKey = SharedSecret (from previous session),
//	salt = InitiatorRandom || ResumptionID (new resumption ID),
//	info = "Sigma2_Resume",
//	len = 16
//
// )
//
// Parameters:
//   - sharedSecret: ECDH shared secret from the previous session
//   - initiatorRandom: 32-byte random from current Sigma1
//   - newResumptionID: 16-byte new resumption ID for this session
//
// Returns the 16-byte S2RK key for computing/verifying Resume2MIC.
func DeriveS2RK(
	sharedSecret []byte,
	initiatorRandom [RandomSize]byte,
	newResumptionID [ResumptionIDSize]byte,
) ([crypto.SymmetricKeySize]byte, error) {
	var result [crypto.SymmetricKeySize]byte

	// Salt = InitiatorRandom || NewResumptionID
	salt := make([]byte, 0, RandomSize+ResumptionIDSize)
	salt = append(salt, initiatorRandom[:]...)
	salt = append(salt, newResumptionID[:]...)

	// Derive key
	key, err := crypto.HKDFSHA256(sharedSecret, salt, S2RKInfo, crypto.SymmetricKeySize)
	if err != nil {
		return result, err
	}

	copy(result[:], key)
	return result, nil
}

// DeriveSessionKeys derives the final session encryption keys.
//
// I2RKey || R2IKey || AttestationChallenge = HKDF-SHA256(
//
//	inputKey = SharedSecret,
//	salt = IPK || TranscriptHash(Msg1 || Msg2 || Msg3),
//	info = "SessionKeys",
//	len = 48
//
// )
//
// Parameters:
//   - sharedSecret: ECDH shared secret (32 bytes)
//   - ipk: Identity Protection Key (16 bytes)
//   - msg1Bytes: Raw TLV bytes of Sigma1 message
//   - msg2Bytes: Raw TLV bytes of Sigma2 message
//   - msg3Bytes: Raw TLV bytes of Sigma3 message
//
// Returns SessionKeys with I2RKey, R2IKey, and AttestationChallenge (each 16 bytes).
func DeriveSessionKeys(
	sharedSecret []byte,
	ipk [crypto.SymmetricKeySize]byte,
	msg1Bytes []byte,
	msg2Bytes []byte,
	msg3Bytes []byte,
) (*SessionKeys, error) {
	// TranscriptHash = SHA256(Msg1 || Msg2 || Msg3)
	transcript := append(msg1Bytes, msg2Bytes...)
	transcript = append(transcript, msg3Bytes...)
	transcriptHash := crypto.SHA256(transcript)

	// Salt = IPK || TranscriptHash
	salt := make([]byte, 0, crypto.SymmetricKeySize+crypto.SHA256LenBytes)
	salt = append(salt, ipk[:]...)
	salt = append(salt, transcriptHash[:]...)

	// Derive 48 bytes: I2RKey (16) || R2IKey (16) || AttestationChallenge (16)
	keys, err := crypto.HKDFSHA256(sharedSecret, salt, SEKeysInfo, 48)
	if err != nil {
		return nil, err
	}

	result := &SessionKeys{}
	copy(result.I2RKey[:], keys[0:16])
	copy(result.R2IKey[:], keys[16:32])
	copy(result.AttestationChallenge[:], keys[32:48])

	return result, nil
}

// DeriveResumptionSessionKeys derives session keys for a resumed session.
//
// I2RKey || R2IKey || AttestationChallenge = HKDF-SHA256(
//
//	inputKey = SharedSecret (from previous session),
//	salt = IPK || TranscriptHash(Msg1 || Sigma2Resume),
//	info = "SessionKeys",
//	len = 48
//
// )
//
// Parameters:
//   - sharedSecret: ECDH shared secret from previous session
//   - ipk: Identity Protection Key (16 bytes)
//   - msg1Bytes: Raw TLV bytes of Sigma1 message (with resumption)
//   - sigma2ResumeBytes: Raw TLV bytes of Sigma2Resume message
//
// Returns SessionKeys with I2RKey, R2IKey, and AttestationChallenge.
func DeriveResumptionSessionKeys(
	sharedSecret []byte,
	ipk [crypto.SymmetricKeySize]byte,
	msg1Bytes []byte,
	sigma2ResumeBytes []byte,
) (*SessionKeys, error) {
	// TranscriptHash = SHA256(Msg1 || Sigma2Resume)
	transcript := append(msg1Bytes, sigma2ResumeBytes...)
	transcriptHash := crypto.SHA256(transcript)

	// Salt = IPK || TranscriptHash
	salt := make([]byte, 0, crypto.SymmetricKeySize+crypto.SHA256LenBytes)
	salt = append(salt, ipk[:]...)
	salt = append(salt, transcriptHash[:]...)

	// Derive 48 bytes: I2RKey (16) || R2IKey (16) || AttestationChallenge (16)
	keys, err := crypto.HKDFSHA256(sharedSecret, salt, SEKeysInfo, 48)
	if err != nil {
		return nil, err
	}

	result := &SessionKeys{}
	copy(result.I2RKey[:], keys[0:16])
	copy(result.R2IKey[:], keys[16:32])
	copy(result.AttestationChallenge[:], keys[32:48])

	return result, nil
}

// EncryptTBEData encrypts To-Be-Encrypted data using AES-128-CCM.
//
// Parameters:
//   - key: 16-byte encryption key (S2K or S3K)
//   - plaintext: Data to encrypt (TBEData2 or TBEData3 TLV bytes)
//   - nonce: 13-byte nonce (Sigma2Nonce or Sigma3Nonce)
//   - aad: Additional authenticated data (empty for CASE)
//
// Returns ciphertext with appended 16-byte MIC.
func EncryptTBEData(
	key [crypto.SymmetricKeySize]byte,
	plaintext []byte,
	nonce []byte,
	aad []byte,
) ([]byte, error) {
	return crypto.AESCCM128Encrypt(key[:], nonce, plaintext, aad)
}

// DecryptTBEData decrypts To-Be-Encrypted data using AES-128-CCM.
//
// Parameters:
//   - key: 16-byte encryption key (S2K or S3K)
//   - ciphertext: Encrypted data with appended MIC
//   - nonce: 13-byte nonce (Sigma2Nonce or Sigma3Nonce)
//   - aad: Additional authenticated data (empty for CASE)
//
// Returns plaintext or error if decryption/verification fails.
func DecryptTBEData(
	key [crypto.SymmetricKeySize]byte,
	ciphertext []byte,
	nonce []byte,
	aad []byte,
) ([]byte, error) {
	return crypto.AESCCM128Decrypt(key[:], nonce, ciphertext, aad)
}

// ComputeResumeMIC computes the MIC for resumption messages.
//
// The MIC is computed using AES-CCM with empty plaintext, producing
// a 16-byte authentication tag.
//
// Parameters:
//   - key: 16-byte key (S1RK or S2RK)
//   - nonce: 13-byte nonce (Resume1Nonce or Resume2Nonce)
//
// Returns 16-byte MIC.
func ComputeResumeMIC(
	key [crypto.SymmetricKeySize]byte,
	nonce []byte,
) ([MICSize]byte, error) {
	var result [MICSize]byte

	// Empty plaintext, empty AAD
	ciphertext, err := crypto.AESCCM128Encrypt(key[:], nonce, nil, nil)
	if err != nil {
		return result, err
	}

	// The ciphertext is just the MIC since plaintext was empty
	copy(result[:], ciphertext)
	return result, nil
}

// VerifyResumeMIC verifies a resumption MIC.
//
// Parameters:
//   - key: 16-byte key (S1RK or S2RK)
//   - nonce: 13-byte nonce (Resume1Nonce or Resume2Nonce)
//   - mic: 16-byte MIC to verify
//
// Returns true if the MIC is valid.
func VerifyResumeMIC(
	key [crypto.SymmetricKeySize]byte,
	nonce []byte,
	mic [MICSize]byte,
) bool {
	expected, err := ComputeResumeMIC(key, nonce)
	if err != nil {
		return false
	}

	return expected == mic
}
