package credentials

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Test vectors from Matter Specification Section 6.5.15

// RCAC test vector from Section 6.5.15.1
const rcacPEM = `-----BEGIN CERTIFICATE-----
MIIBnTCCAUOgAwIBAgIIWeqmMpR/VBwwCgYIKoZIzj0EAwIwIjEgMB4GCisGAQQB
gqJ8AQQMEENBQ0FDQUNBMDAwMDAwMDEwHhcNMjAxMDE1MTQyMzQzWhcNNDAxMDE1
MTQyMzQyWjAiMSAwHgYKKwYBBAGConwBBAwQQ0FDQUNBQ0EwMDAwMDAwMTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABBNTo7PvHacIxJCASAFOQH1ZkM4ivE6zPppa
yyWoVgPrptzYITZmpORPWsoT63Z/r6fc3dwzQR+CowtUPdHSS6ijYzBhMA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQTr4GrNzdLLtKp
ZJsSt6OkKH4VHTAfBgNVHSMEGDAWgBQTr4GrNzdLLtKpZJsSt6OkKH4VHTAKBggq
hkjOPQQDAgNIADBFAiBFgWRGbI8ZWrwKu3xstaJ6g/QdN/jVO+7FIKvSoNoFCQIh
ALinwlwELjDPZNww/jNOEgAZZk5RUEkTT1eBI4RE/HUx
-----END CERTIFICATE-----`

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

// ICAC test vector from Section 6.5.15.2
const icacPEM = `-----BEGIN CERTIFICATE-----
MIIBnTCCAUOgAwIBAgIILbREhVZBrt8wCgYIKoZIzj0EAwIwIjEgMB4GCisGAQQB
gqJ8AQQMEENBQ0FDQUNBMDAwMDAwMDEwHhcNMjAxMDE1MTQyMzQzWhcNNDAxMDE1
MTQyMzQyWjAiMSAwHgYKKwYBBAGConwBAwwQQ0FDQUNBQ0EwMDAwMDAwMzBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABMXQhhu4+QxAXBIxTkxevuqTn3J3S8wzI54v
Wfb0avjcfUaCoOPMxkbm3ynqhr9WKucgqJgzfTg/MsCgnkFgGeqjYzBhMA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBRTUtcFnpwVpQiQ
aGKGSAGinx9B0zAfBgNVHSMEGDAWgBQTr4GrNzdLLtKpZJsSt6OkKH4VHTAKBggq
hkjOPQQDAgNIADBFAiEAhBoG1Dten+zSToexJE61HGos8g2bXmugfxHmAC9+DKMC
IE4ypgLDYJ0AktNIvb0ZihFGRr1BzxA3g2Qa4l4/I/0m
-----END CERTIFICATE-----`

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

// NOC test vector from Section 6.5.15.3
const nocPEM = `-----BEGIN CERTIFICATE-----
MIIB4DCCAYagAwIBAgIIPvz/FwK5oXowCgYIKoZIzj0EAwIwIjEgMB4GCisGAQQB
gqJ8AQMMEENBQ0FDQUNBMDAwMDAwMDMwHhcNMjAxMDE1MTQyMzQzWhcNNDAxMDE1
MTQyMzQyWjBEMSAwHgYKKwYBBAGConwBAQwQREVERURFREUwMDAxMDAwMTEgMB4G
CisGAQQBgqJ8AQUMEEZBQjAwMDAwMDAwMDAwMUQwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASaKiFvs53WtvohG4NciePmr7ZsFPdYMZVPn/T3o/ARLIoNjq8pxlMp
TUju4HCKAyzKOTk8OntG8YGuoHj+rYODo4GDMIGAMAwGA1UdEwEB/wQCMAAwDgYD
VR0PAQH/BAQDAgeAMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAd
BgNVHQ4EFgQUn1Wia35DA+YIg+kTv5T0+14qYWEwHwYDVR0jBBgwFoAUU1LXBZ6c
FaUIkGhihkgBop8fQdMwCgYIKoZIzj0EAwIDSAAwRQIgeVXCAmMLS6TVkSUmMi/f
KPie3+WvnA5XK9ihSqq7TRICIQC4PKF8ewX7Fkt315xSlhMxa8/ReJXksqTyQEuY
FzJxWQ==
-----END CERTIFICATE-----`

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

func TestRCACConversion(t *testing.T) {
	// Parse PEM to Matter Certificate
	cert, err := X509PEMToMatter([]byte(rcacPEM))
	if err != nil {
		t.Fatalf("X509PEMToMatter failed: %v", err)
	}

	// Verify certificate type
	if cert.Type() != CertTypeRCAC {
		t.Errorf("expected RCAC, got %v", cert.Type())
	}

	// Verify key fields
	if cert.SigAlgo != SignatureAlgoECDSASHA256 {
		t.Errorf("expected ECDSA-SHA256, got %v", cert.SigAlgo)
	}
	if cert.PubKeyAlgo != PublicKeyAlgoEC {
		t.Errorf("expected EC, got %v", cert.PubKeyAlgo)
	}
	if cert.ECCurveID != EllipticCurvePrime256v1 {
		t.Errorf("expected prime256v1, got %v", cert.ECCurveID)
	}

	// Verify RCAC ID
	rcacID := cert.Subject.GetRCACID()
	if rcacID != 0xCACACACA00000001 {
		t.Errorf("expected RCAC ID 0xCACACACA00000001, got 0x%X", rcacID)
	}

	// Verify this is a CA cert
	if !cert.IsCA() {
		t.Error("expected IsCA to be true")
	}

	// Verify key usage includes keyCertSign and cRLSign
	if cert.Extensions.KeyUsage == nil {
		t.Fatal("expected KeyUsage extension")
	}
	ku := cert.Extensions.KeyUsage.Usage
	if !ku.HasFlag(KeyUsageKeyCertSign) {
		t.Error("expected keyCertSign flag")
	}
	if !ku.HasFlag(KeyUsageCRLSign) {
		t.Error("expected cRLSign flag")
	}

	// Verify subject key ID matches authority key ID (self-signed)
	if cert.Extensions.SubjectKeyID == nil {
		t.Fatal("expected SubjectKeyID extension")
	}
	if cert.Extensions.AuthorityKeyID == nil {
		t.Fatal("expected AuthorityKeyID extension")
	}
	if !bytes.Equal(cert.SubjectKeyID(), cert.AuthorityKeyID()) {
		t.Error("RCAC subject key ID should match authority key ID")
	}

	// Encode to TLV
	tlvBytes, err := cert.EncodeTLV()
	if err != nil {
		t.Fatalf("EncodeTLV failed: %v", err)
	}

	// Compare with expected TLV
	expectedTLV := hexToBytes(rcacTLVHex)
	if !bytes.Equal(tlvBytes, expectedTLV) {
		t.Errorf("TLV mismatch\ngot:      %s\nexpected: %s",
			hex.EncodeToString(tlvBytes),
			hex.EncodeToString(expectedTLV))
	}
}

func TestICACConversion(t *testing.T) {
	cert, err := X509PEMToMatter([]byte(icacPEM))
	if err != nil {
		t.Fatalf("X509PEMToMatter failed: %v", err)
	}

	// Verify certificate type
	if cert.Type() != CertTypeICAC {
		t.Errorf("expected ICAC, got %v", cert.Type())
	}

	// Verify ICAC ID
	icacID := cert.Subject.GetICACID()
	if icacID != 0xCACACACA00000003 {
		t.Errorf("expected ICAC ID 0xCACACACA00000003, got 0x%X", icacID)
	}

	// Verify issuer RCAC ID
	issuerRCACID := cert.Issuer.GetRCACID()
	if issuerRCACID != 0xCACACACA00000001 {
		t.Errorf("expected issuer RCAC ID 0xCACACACA00000001, got 0x%X", issuerRCACID)
	}

	// Verify this is a CA cert
	if !cert.IsCA() {
		t.Error("expected IsCA to be true")
	}

	// Encode to TLV
	tlvBytes, err := cert.EncodeTLV()
	if err != nil {
		t.Fatalf("EncodeTLV failed: %v", err)
	}

	// Compare with expected TLV
	expectedTLV := hexToBytes(icacTLVHex)
	if !bytes.Equal(tlvBytes, expectedTLV) {
		t.Errorf("TLV mismatch\ngot:      %s\nexpected: %s",
			hex.EncodeToString(tlvBytes),
			hex.EncodeToString(expectedTLV))
	}
}

func TestNOCConversion(t *testing.T) {
	cert, err := X509PEMToMatter([]byte(nocPEM))
	if err != nil {
		t.Fatalf("X509PEMToMatter failed: %v", err)
	}

	// Verify certificate type
	if cert.Type() != CertTypeNOC {
		t.Errorf("expected NOC, got %v", cert.Type())
	}

	// Verify Node ID
	nodeID := cert.Subject.GetNodeID()
	if nodeID != 0xDEDEDEDE00010001 {
		t.Errorf("expected Node ID 0xDEDEDEDE00010001, got 0x%X", nodeID)
	}

	// Verify Fabric ID
	fabricID := cert.Subject.GetFabricID()
	if fabricID != 0xFAB000000000001D {
		t.Errorf("expected Fabric ID 0xFAB000000000001D, got 0x%X", fabricID)
	}

	// Verify issuer ICAC ID
	issuerICACID := cert.Issuer.GetICACID()
	if issuerICACID != 0xCACACACA00000003 {
		t.Errorf("expected issuer ICAC ID 0xCACACACA00000003, got 0x%X", issuerICACID)
	}

	// Verify this is NOT a CA cert
	if cert.IsCA() {
		t.Error("expected IsCA to be false for NOC")
	}

	// Verify key usage has digitalSignature only
	if cert.Extensions.KeyUsage == nil {
		t.Fatal("expected KeyUsage extension")
	}
	ku := cert.Extensions.KeyUsage.Usage
	if ku != KeyUsageDigitalSignature {
		t.Errorf("expected only digitalSignature, got %v", ku)
	}

	// Verify extended key usage has clientAuth and serverAuth
	if cert.Extensions.ExtendedKeyUsage == nil {
		t.Fatal("expected ExtendedKeyUsage extension")
	}
	eku := cert.Extensions.ExtendedKeyUsage.KeyPurposes
	if len(eku) != 2 {
		t.Errorf("expected 2 key purposes, got %d", len(eku))
	}

	// Encode to TLV
	tlvBytes, err := cert.EncodeTLV()
	if err != nil {
		t.Fatalf("EncodeTLV failed: %v", err)
	}

	// Compare with expected TLV
	expectedTLV := hexToBytes(nocTLVHex)
	if !bytes.Equal(tlvBytes, expectedTLV) {
		t.Errorf("TLV mismatch\ngot:      %s\nexpected: %s",
			hex.EncodeToString(tlvBytes),
			hex.EncodeToString(expectedTLV))
	}
}

func TestTLVDecoding(t *testing.T) {
	// Test decoding the TLV directly
	tlvBytes := hexToBytes(rcacTLVHex)
	cert, err := DecodeTLV(tlvBytes)
	if err != nil {
		t.Fatalf("DecodeTLV failed: %v", err)
	}

	// Verify key fields
	if cert.Type() != CertTypeRCAC {
		t.Errorf("expected RCAC, got %v", cert.Type())
	}

	rcacID := cert.Subject.GetRCACID()
	if rcacID != 0xCACACACA00000001 {
		t.Errorf("expected RCAC ID 0xCACACACA00000001, got 0x%X", rcacID)
	}

	// Re-encode and verify roundtrip
	reencoded, err := cert.EncodeTLV()
	if err != nil {
		t.Fatalf("EncodeTLV failed: %v", err)
	}

	if !bytes.Equal(reencoded, tlvBytes) {
		t.Errorf("TLV roundtrip failed\ngot:      %s\nexpected: %s",
			hex.EncodeToString(reencoded),
			hex.EncodeToString(tlvBytes))
	}
}

func TestRCACFields(t *testing.T) {
	cert, err := X509PEMToMatter([]byte(rcacPEM))
	if err != nil {
		t.Fatalf("X509PEMToMatter failed: %v", err)
	}

	// Verify serial number
	expectedSerial := hexToBytes("59eaa632947f541c")
	if !bytes.Equal(cert.SerialNum, expectedSerial) {
		t.Errorf("serial mismatch: got %x, expected %x", cert.SerialNum, expectedSerial)
	}

	// Verify public key (65 bytes uncompressed)
	if len(cert.ECPubKey) != 65 {
		t.Errorf("expected 65-byte public key, got %d", len(cert.ECPubKey))
	}
	if cert.ECPubKey[0] != 0x04 {
		t.Errorf("expected uncompressed public key (0x04), got 0x%02x", cert.ECPubKey[0])
	}

	// Verify signature (64 bytes raw)
	if len(cert.Signature) != 64 {
		t.Errorf("expected 64-byte signature, got %d", len(cert.Signature))
	}

	// Verify validity times
	// NotBefore: Oct 15 14:23:43 2020 GMT -> 0x271B17EF in Matter epoch
	if cert.NotBefore != 0x271B17EF {
		t.Errorf("expected NotBefore 0x271B17EF, got 0x%X", cert.NotBefore)
	}

	// NotAfter: Oct 15 14:23:42 2040 GMT -> 0x4CB9B56E in Matter epoch
	if cert.NotAfter != 0x4CB9B56E {
		t.Errorf("expected NotAfter 0x4CB9B56E, got 0x%X", cert.NotAfter)
	}
}

func TestHexStringConversion(t *testing.T) {
	tests := []struct {
		name    string
		value   uint64
		byteLen int
		hexStr  string
	}{
		{"node-id", 0xDEDEDEDE00010001, 8, "DEDEDEDE00010001"},
		{"fabric-id", 0xFAB000000000001D, 8, "FAB000000000001D"},
		{"rcac-id", 0xCACACACA00000001, 8, "CACACACA00000001"},
		{"noc-cat", 0x00AA33CC, 4, "00AA33CC"},
		{"small-value", 0x0123, 8, "0000000000000123"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Test to hex string
			got := MatterSpecificToHexString(tc.value, tc.byteLen)
			if got != tc.hexStr {
				t.Errorf("MatterSpecificToHexString: got %s, expected %s", got, tc.hexStr)
			}

			// Test from hex string
			parsed, err := HexStringToMatterSpecific(tc.hexStr)
			if err != nil {
				t.Fatalf("HexStringToMatterSpecific failed: %v", err)
			}
			if parsed != tc.value {
				t.Errorf("HexStringToMatterSpecific: got 0x%X, expected 0x%X", parsed, tc.value)
			}
		})
	}
}

func TestDNAttributeString(t *testing.T) {
	tests := []struct {
		attr     DNAttribute
		expected string
	}{
		{NewDNString(TagDNCommonName, "Test CN"), "CN=Test CN"},
		{NewDNString(TagDNOrgName, "Test Org"), "O=Test Org"},
		{NewDNUint64(TagDNMatterNodeID, 0xDEDEDEDE00010001), "matter-node-id=0xDEDEDEDE00010001"},
		{NewDNUint64(TagDNMatterFabricID, 0xFAB000000000001D), "matter-fabric-id=0xFAB000000000001D"},
		{NewDNUint64(TagDNMatterRCACID, 0xCACACACA00000001), "matter-rcac-id=0xCACACACA00000001"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			got := tc.attr.String()
			if got != tc.expected {
				t.Errorf("got %s, expected %s", got, tc.expected)
			}
		})
	}
}
