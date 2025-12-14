package fabric

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/backkem/matter/pkg/credentials"
)

// Test vectors from Matter Specification Section 6.5.15
// These are the same vectors used in the credentials package.

var rcacTLVHex = strings.ReplaceAll(`15 30 01 08 59 ea a6 32 94 7f 54 1c 24 02 01 37 03 27 14 01 00 00 00 ca
ca ca ca 18 26 04 ef 17 1b 27 26 05 6e b5 b9 4c 37 06 27 14 01 00 00 00
ca ca ca ca 18 24 07 01 24 08 01 30 09 41 04 13 53 a3 b3 ef 1d a7 08 c4
90 80 48 01 4e 40 7d 59 90 ce 22 bc 4e b3 3e 9a 5a cb 25 a8 56 03 eb a6
dc d8 21 36 66 a4 e4 4f 5a ca 13 eb 76 7f af a7 dc dd dc 33 41 1f 82 a3
0b 54 3d d1 d2 4b a8 37 0a 35 01 29 01 18 24 02 60 30 04 14 13 af 81 ab
37 37 4b 2e d2 a9 64 9b 12 b7 a3 a4 28 7e 15 1d 30 05 14 13 af 81 ab 37
37 4b 2e d2 a9 64 9b 12 b7 a3 a4 28 7e 15 1d 18 30 0b 40 45 81 64 46 6c
8f 19 5a bc 0a bb 7c 6c b5 a2 7a 83 f4 1d 37 f8 d5 3b ee c5 20 ab d2 a0
da 05 09 b8 a7 c2 5c 04 2e 30 cf 64 dc 30 fe 33 4e 12 00 19 66 4e 51 50
49 13 4f 57 81 23 84 44 fc 75 31 18`, " ", "")

var icacTLVHex = strings.ReplaceAll(`15 30 01 08 2d b4 44 85 56 41 ae df 24 02 01 37 03 27 14 01 00 00 00 ca
ca ca ca 18 26 04 ef 17 1b 27 26 05 6e b5 b9 4c 37 06 27 13 03 00 00 00
ca ca ca ca 18 24 07 01 24 08 01 30 09 41 04 c5 d0 86 1b b8 f9 0c 40 5c
12 31 4e 4c 5e be ea 93 9f 72 77 4b cc 33 23 9e 2f 59 f6 f4 6a f8 dc 7d
46 82 a0 e3 cc c6 46 e6 df 29 ea 86 bf 56 2a e7 20 a8 98 33 7d 38 3f 32
c0 a0 9e 41 60 19 ea 37 0a 35 01 29 01 18 24 02 60 30 04 14 53 52 d7 05
9e 9c 15 a5 08 90 68 62 86 48 01 a2 9f 1f 41 d3 30 05 14 13 af 81 ab 37
37 4b 2e d2 a9 64 9b 12 b7 a3 a4 28 7e 15 1d 18 30 0b 40 84 1a 06 d4 3b
5e 9f ec d2 4e 87 b1 24 4e b5 1c 6a 2c f2 0d 9b 5e 6b a0 7f 11 e6 00 2f
7e 0c a3 4e 32 a6 02 c3 60 9d 00 92 d3 48 bd bd 19 8a 11 46 46 bd 41 cf
10 37 83 64 1a e2 5e 3f 23 fd 26 18`, " ", "")

var nocTLVHex = strings.ReplaceAll(`15 30 01 08 3e fc ff 17 02 b9 a1 7a 24 02 01 37 03 27 13 03 00 00 00 ca
ca ca ca 18 26 04 ef 17 1b 27 26 05 6e b5 b9 4c 37 06 27 11 01 00 01 00
de de de de 27 15 1d 00 00 00 00 00 b0 fa 18 24 07 01 24 08 01 30 09 41
04 9a 2a 21 6f b3 9d d6 b6 fa 21 1b 83 5c 89 e3 e6 af b6 6c 14 f7 58 31
95 4f 9f f4 f7 a3 f0 11 2c 8a 0d 8e af 29 c6 53 29 4d 48 ee e0 70 8a 03
2c ca 39 39 3c 3a 7b 46 f1 81 ae a0 78 fe ad 83 83 37 0a 35 01 28 01 18
24 02 01 36 03 04 02 04 01 18 30 04 14 9f 55 a2 6b 7e 43 03 e6 08 83 e9
13 bf 94 f4 fb 5e 2a 61 61 30 05 14 53 52 d7 05 9e 9c 15 a5 08 90 68 62
86 48 01 a2 9f 1f 41 d3 18 30 0b 40 79 55 c2 02 63 0b 4b a4 d5 91 25 26
32 2f df 28 f8 9e df e5 af 9c 0e 57 2b d8 a1 4a aa bb 4d 12 b8 3c a1 7c
7b 05 fb 16 4b 77 d7 9c 52 96 13 31 6b cf d1 78 95 e4 b2 a4 f2 40 4b 98
17 32 71 59 18`, " ", "")

func hexToBytes(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\n", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestParseCertificate(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	icacTLV := hexToBytes(icacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)

	tests := []struct {
		name         string
		certTLV      []byte
		expectedType credentials.CertificateType
	}{
		{"RCAC", rcacTLV, credentials.CertTypeRCAC},
		{"ICAC", icacTLV, credentials.CertTypeICAC},
		{"NOC", nocTLV, credentials.CertTypeNOC},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ParseCertificate(tt.certTLV)
			if err != nil {
				t.Fatalf("ParseCertificate failed: %v", err)
			}
			if cert.Type() != tt.expectedType {
				t.Errorf("expected %v, got %v", tt.expectedType, cert.Type())
			}
		})
	}
}

func TestExtractFabricID(t *testing.T) {
	// The spec test vectors use fabric ID 0xFAB000000000001D
	// Actually looking at the NOC: matter-fabric-id is at offset with value
	// From the NOC hex, the fabric-id tag is 27 15 which is context tag 21 (matter-fabric-id)
	// The value is: 1d 00 00 00 00 00 b0 fa -> little-endian uint64 = 0xFAB000000000001D

	nocTLV := hexToBytes(nocTLVHex)
	cert, err := ParseCertificate(nocTLV)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	fabricID, err := ExtractFabricID(cert)
	if err != nil {
		t.Fatalf("ExtractFabricID failed: %v", err)
	}

	// Expected fabric ID from the spec test vector NOC
	expectedFabricID := FabricID(0xFAB000000000001D)
	if fabricID != expectedFabricID {
		t.Errorf("fabric ID mismatch: got 0x%X, expected 0x%X", fabricID, expectedFabricID)
	}
}

func TestExtractNodeID(t *testing.T) {
	// From the NOC hex, the node-id is matter-node-id (tag 17/0x11)
	// The value is: 01 00 01 00 de de de de -> little-endian uint64 = 0xDEDEDEDE00010001

	nocTLV := hexToBytes(nocTLVHex)
	cert, err := ParseCertificate(nocTLV)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	nodeID, err := ExtractNodeID(cert)
	if err != nil {
		t.Fatalf("ExtractNodeID failed: %v", err)
	}

	// Expected node ID from the spec test vector NOC
	expectedNodeID := NodeID(0xDEDEDEDE00010001)
	if nodeID != expectedNodeID {
		t.Errorf("node ID mismatch: got 0x%X, expected 0x%X", nodeID, expectedNodeID)
	}

	// Verify it's an operational node ID
	if !nodeID.IsOperational() {
		t.Errorf("expected operational node ID")
	}
}

func TestExtractNodeID_NonNOC(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	cert, err := ParseCertificate(rcacTLV)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	_, err = ExtractNodeID(cert)
	if err == nil {
		t.Error("expected error for RCAC")
	}
}

func TestExtractRootPublicKey(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	cert, err := ParseCertificate(rcacTLV)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	pubKey, err := ExtractRootPublicKey(cert)
	if err != nil {
		t.Fatalf("ExtractRootPublicKey failed: %v", err)
	}

	// Verify it starts with 0x04 (uncompressed point format)
	if pubKey[0] != 0x04 {
		t.Errorf("expected uncompressed point prefix 0x04, got 0x%02X", pubKey[0])
	}

	// Verify length
	if len(pubKey) != RootPublicKeySize {
		t.Errorf("expected %d bytes, got %d", RootPublicKeySize, len(pubKey))
	}
}

func TestValidateNOCChain_WithICAC(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	icacTLV := hexToBytes(icacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)

	err := ValidateNOCChain(rcacTLV, nocTLV, icacTLV)
	if err != nil {
		t.Errorf("ValidateNOCChain failed: %v", err)
	}
}

func TestValidateNOCChain_InvalidCertType(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	icacTLV := hexToBytes(icacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)

	// Pass NOC as root - should fail
	err := ValidateNOCChain(nocTLV, nocTLV, icacTLV)
	if err == nil {
		t.Error("expected error when NOC passed as root")
	}

	// Pass RCAC as NOC - should fail
	err = ValidateNOCChain(rcacTLV, rcacTLV, icacTLV)
	if err == nil {
		t.Error("expected error when RCAC passed as NOC")
	}
}

func TestValidateNOCChain_InvalidCert(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)

	// Pass empty cert
	err := ValidateNOCChain([]byte{}, nocTLV, nil)
	if err == nil {
		t.Error("expected error for empty root cert")
	}

	err = ValidateNOCChain(rcacTLV, []byte{}, nil)
	if err == nil {
		t.Error("expected error for empty NOC")
	}

	// Pass garbage
	err = ValidateNOCChain([]byte{0xFF, 0xFF, 0xFF}, nocTLV, nil)
	if err == nil {
		t.Error("expected error for invalid root cert")
	}
}

func TestExtractChainInfo(t *testing.T) {
	rcacTLV := hexToBytes(rcacTLVHex)
	nocTLV := hexToBytes(nocTLVHex)

	info, err := ExtractChainInfo(rcacTLV, nocTLV)
	if err != nil {
		t.Fatalf("ExtractChainInfo failed: %v", err)
	}

	// Fabric ID comes from NOC (RCAC doesn't have fabric ID in this test vector)
	// NOC subject: matter-node-id = 0xDEDEDEDE00010001, matter-fabric-id = 0xFAB000000000001D
	expectedFabricID := FabricID(0xFAB000000000001D)
	if info.FabricID != expectedFabricID {
		t.Errorf("fabric ID mismatch: got 0x%X, expected 0x%X", info.FabricID, expectedFabricID)
	}

	// Node ID should be from NOC
	expectedNodeID := NodeID(0xDEDEDEDE00010001)
	if info.NodeID != expectedNodeID {
		t.Errorf("node ID mismatch: got 0x%X, expected 0x%X", info.NodeID, expectedNodeID)
	}

	// Root public key should start with 0x04
	if info.RootPublicKey[0] != 0x04 {
		t.Errorf("expected uncompressed point prefix 0x04, got 0x%02X", info.RootPublicKey[0])
	}
}

func TestExtractFabricIDOptional(t *testing.T) {
	// RCAC doesn't have fabric ID
	rcacTLV := hexToBytes(rcacTLVHex)
	rcacCert, err := ParseCertificate(rcacTLV)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	_, found := ExtractFabricIDOptional(rcacCert)
	if found {
		t.Error("expected RCAC to not have fabric ID")
	}

	// NOC has fabric ID
	nocTLV := hexToBytes(nocTLVHex)
	nocCert, err := ParseCertificate(nocTLV)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	fabricID, found := ExtractFabricIDOptional(nocCert)
	if !found {
		t.Error("expected NOC to have fabric ID")
	}
	if fabricID != FabricID(0xFAB000000000001D) {
		t.Errorf("fabric ID mismatch: got 0x%X", fabricID)
	}
}
