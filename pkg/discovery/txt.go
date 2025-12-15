package discovery

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/backkem/matter/pkg/fabric"
)

// TXT record key constants from Spec Section 4.3.1.4 and 4.3.2.5.
const (
	// TXTKeyDiscriminator is the discriminator key (12-bit value).
	TXTKeyDiscriminator = "D"

	// TXTKeyCommissioningMode is the commissioning mode key.
	TXTKeyCommissioningMode = "CM"

	// TXTKeyVendorProduct is the vendor/product ID key (format: "VID+PID").
	TXTKeyVendorProduct = "VP"

	// TXTKeyDeviceType is the device type key.
	TXTKeyDeviceType = "DT"

	// TXTKeyDeviceName is the device name key (max 32 chars).
	TXTKeyDeviceName = "DN"

	// TXTKeyIdleInterval is the sleepy idle interval key (milliseconds).
	TXTKeyIdleInterval = "SII"

	// TXTKeyActiveInterval is the sleepy active interval key (milliseconds).
	TXTKeyActiveInterval = "SAI"

	// TXTKeyTCPSupported indicates TCP support.
	TXTKeyTCPSupported = "T"

	// TXTKeyICDMode is the ICD operating mode key.
	TXTKeyICDMode = "ICD"

	// TXTKeyPairingHint is the pairing hint bitmap.
	TXTKeyPairingHint = "PH"

	// TXTKeyPairingInstructions is the pairing instructions key.
	TXTKeyPairingInstructions = "PI"

	// TXTKeyCommissionerPasscode indicates commissioner passcode support.
	TXTKeyCommissionerPasscode = "CP"

	// TXTKeyJointFabric indicates Joint Fabric capabilities.
	TXTKeyJointFabric = "JF"
)

// MaxDeviceNameLength is the maximum length of the device name.
// Spec Section 4.3.1.9
const MaxDeviceNameLength = 32

// MaxDiscriminator is the maximum valid discriminator value (12 bits).
const MaxDiscriminator = 0xFFF

// CommissionableTXT holds TXT records for _matterc._udp (Spec 4.3.1.4).
type CommissionableTXT struct {
	// Discriminator is the 12-bit discriminator (required).
	// Spec Section 4.3.1.5
	Discriminator uint16

	// CommissioningMode indicates the current commissioning mode.
	// Spec Section 4.3.1.3
	CommissioningMode CommissioningMode

	// VendorID is the vendor identifier (optional, from VP key).
	// Spec Section 4.3.1.6
	VendorID fabric.VendorID

	// ProductID is the product identifier (optional, from VP key).
	// Spec Section 4.3.1.6
	ProductID uint16

	// DeviceType is the primary device type identifier (optional).
	// Spec Section 4.3.1.8
	DeviceType uint32

	// DeviceName is the human-readable device name (optional, max 32 chars).
	// Spec Section 4.3.1.9
	DeviceName string

	// IdleInterval is the SESSION_IDLE_INTERVAL in milliseconds (optional).
	// Spec Section 4.3.1.10
	IdleInterval time.Duration

	// ActiveInterval is the SESSION_ACTIVE_INTERVAL in milliseconds (optional).
	// Spec Section 4.3.1.11
	ActiveInterval time.Duration

	// TCPSupported indicates whether the node supports TCP (optional).
	// Spec Section 4.3.4
	TCPSupported bool

	// ICDMode is the ICD operating mode (optional).
	// Spec Section 4.3.4
	ICDMode ICDMode
	ICDSet  bool // Whether ICD was explicitly set

	// PairingHint is the bitmap of pairing methods (optional).
	// Spec Section 4.3.1.12
	PairingHint uint16

	// PairingInstructions provides additional pairing info (optional).
	// Spec Section 4.3.1.14
	PairingInstructions string
}

// Encode converts the TXT record to DNS-SD format strings.
func (c *CommissionableTXT) Encode() []string {
	var txt []string

	// D is required
	txt = append(txt, fmt.Sprintf("%s=%d", TXTKeyDiscriminator, c.Discriminator))

	// CM
	txt = append(txt, fmt.Sprintf("%s=%d", TXTKeyCommissioningMode, c.CommissioningMode))

	// VP (VendorID+ProductID)
	if c.VendorID != 0 || c.ProductID != 0 {
		txt = append(txt, fmt.Sprintf("%s=%d+%d", TXTKeyVendorProduct, c.VendorID, c.ProductID))
	}

	// DT
	if c.DeviceType != 0 {
		txt = append(txt, fmt.Sprintf("%s=%d", TXTKeyDeviceType, c.DeviceType))
	}

	// DN
	if c.DeviceName != "" {
		name := c.DeviceName
		if len(name) > MaxDeviceNameLength {
			name = name[:MaxDeviceNameLength]
		}
		txt = append(txt, fmt.Sprintf("%s=%s", TXTKeyDeviceName, name))
	}

	// SII (in milliseconds)
	if c.IdleInterval > 0 {
		txt = append(txt, fmt.Sprintf("%s=%d", TXTKeyIdleInterval, c.IdleInterval.Milliseconds()))
	}

	// SAI (in milliseconds)
	if c.ActiveInterval > 0 {
		txt = append(txt, fmt.Sprintf("%s=%d", TXTKeyActiveInterval, c.ActiveInterval.Milliseconds()))
	}

	// T
	if c.TCPSupported {
		txt = append(txt, fmt.Sprintf("%s=1", TXTKeyTCPSupported))
	}

	// ICD
	if c.ICDSet {
		txt = append(txt, fmt.Sprintf("%s=%d", TXTKeyICDMode, c.ICDMode))
	}

	// PH
	if c.PairingHint != 0 {
		txt = append(txt, fmt.Sprintf("%s=%d", TXTKeyPairingHint, c.PairingHint))
	}

	// PI
	if c.PairingInstructions != "" {
		txt = append(txt, fmt.Sprintf("%s=%s", TXTKeyPairingInstructions, c.PairingInstructions))
	}

	return txt
}

// Validate checks that the TXT record values are within spec limits.
func (c *CommissionableTXT) Validate() error {
	if c.Discriminator > MaxDiscriminator {
		return ErrInvalidDiscriminator
	}
	if len(c.DeviceName) > MaxDeviceNameLength {
		return ErrInvalidDeviceName
	}
	return nil
}

// ShortDiscriminator returns the 4-bit short discriminator.
// Spec Section 4.3.1.5: short = (long >> 8) & 0xF
func (c *CommissionableTXT) ShortDiscriminator() uint8 {
	return uint8((c.Discriminator >> 8) & 0xF)
}

// OperationalTXT holds TXT records for _matter._tcp (Spec 4.3.2.5).
type OperationalTXT struct {
	// IdleInterval is the SESSION_IDLE_INTERVAL in milliseconds (optional).
	IdleInterval time.Duration

	// ActiveInterval is the SESSION_ACTIVE_INTERVAL in milliseconds (optional).
	ActiveInterval time.Duration

	// TCPSupported indicates whether the node supports TCP (optional).
	TCPSupported bool

	// ICDMode is the ICD operating mode (optional).
	ICDMode ICDMode
	ICDSet  bool // Whether ICD was explicitly set
}

// Encode converts the TXT record to DNS-SD format strings.
func (o *OperationalTXT) Encode() []string {
	var txt []string

	// SII (in milliseconds)
	if o.IdleInterval > 0 {
		txt = append(txt, fmt.Sprintf("%s=%d", TXTKeyIdleInterval, o.IdleInterval.Milliseconds()))
	}

	// SAI (in milliseconds)
	if o.ActiveInterval > 0 {
		txt = append(txt, fmt.Sprintf("%s=%d", TXTKeyActiveInterval, o.ActiveInterval.Milliseconds()))
	}

	// T
	if o.TCPSupported {
		txt = append(txt, fmt.Sprintf("%s=1", TXTKeyTCPSupported))
	}

	// ICD
	if o.ICDSet {
		txt = append(txt, fmt.Sprintf("%s=%d", TXTKeyICDMode, o.ICDMode))
	}

	return txt
}

// CommissionerTXT holds TXT records for _matterd._udp (Spec 4.3.3).
type CommissionerTXT struct {
	// VendorID is the vendor identifier (optional).
	VendorID fabric.VendorID

	// ProductID is the product identifier (optional).
	ProductID uint16

	// DeviceType is the primary device type identifier (optional).
	DeviceType uint32

	// DeviceName is the human-readable device name (optional, max 32 chars).
	DeviceName string

	// CommissionerPasscode indicates whether commissioner passcode is supported.
	// Spec Section 4.3.3
	CommissionerPasscode bool
}

// Encode converts the TXT record to DNS-SD format strings.
func (c *CommissionerTXT) Encode() []string {
	var txt []string

	// VP (VendorID+ProductID)
	if c.VendorID != 0 || c.ProductID != 0 {
		txt = append(txt, fmt.Sprintf("%s=%d+%d", TXTKeyVendorProduct, c.VendorID, c.ProductID))
	}

	// DT
	if c.DeviceType != 0 {
		txt = append(txt, fmt.Sprintf("%s=%d", TXTKeyDeviceType, c.DeviceType))
	}

	// DN
	if c.DeviceName != "" {
		name := c.DeviceName
		if len(name) > MaxDeviceNameLength {
			name = name[:MaxDeviceNameLength]
		}
		txt = append(txt, fmt.Sprintf("%s=%s", TXTKeyDeviceName, name))
	}

	// CP
	if c.CommissionerPasscode {
		txt = append(txt, fmt.Sprintf("%s=1", TXTKeyCommissionerPasscode))
	}

	return txt
}

// Validate checks that the TXT record values are within spec limits.
func (c *CommissionerTXT) Validate() error {
	if len(c.DeviceName) > MaxDeviceNameLength {
		return ErrInvalidDeviceName
	}
	return nil
}

// ParseTXT parses raw TXT record strings into a map.
func ParseTXT(records []string) map[string]string {
	result := make(map[string]string)
	for _, record := range records {
		if idx := strings.IndexByte(record, '='); idx > 0 {
			key := record[:idx]
			value := record[idx+1:]
			result[key] = value
		}
	}
	return result
}

// ParseCommissionableTXT parses raw TXT records into CommissionableTXT.
func ParseCommissionableTXT(records []string) (*CommissionableTXT, error) {
	m := ParseTXT(records)
	txt := &CommissionableTXT{}

	// D (required)
	if v, ok := m[TXTKeyDiscriminator]; ok {
		d, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil, ErrInvalidTXTRecord
		}
		if d > MaxDiscriminator {
			return nil, ErrInvalidDiscriminator
		}
		txt.Discriminator = uint16(d)
	}

	// CM
	if v, ok := m[TXTKeyCommissioningMode]; ok {
		cm, err := strconv.ParseInt(v, 10, 8)
		if err != nil {
			return nil, ErrInvalidTXTRecord
		}
		txt.CommissioningMode = CommissioningMode(cm)
	}

	// VP
	if v, ok := m[TXTKeyVendorProduct]; ok {
		if err := parseVendorProduct(v, &txt.VendorID, &txt.ProductID); err != nil {
			return nil, err
		}
	}

	// DT
	if v, ok := m[TXTKeyDeviceType]; ok {
		dt, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, ErrInvalidTXTRecord
		}
		txt.DeviceType = uint32(dt)
	}

	// DN
	if v, ok := m[TXTKeyDeviceName]; ok {
		txt.DeviceName = v
	}

	// SII
	if v, ok := m[TXTKeyIdleInterval]; ok {
		sii, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, ErrInvalidTXTRecord
		}
		txt.IdleInterval = time.Duration(sii) * time.Millisecond
	}

	// SAI
	if v, ok := m[TXTKeyActiveInterval]; ok {
		sai, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, ErrInvalidTXTRecord
		}
		txt.ActiveInterval = time.Duration(sai) * time.Millisecond
	}

	// T
	if v, ok := m[TXTKeyTCPSupported]; ok {
		txt.TCPSupported = v == "1"
	}

	// ICD
	if v, ok := m[TXTKeyICDMode]; ok {
		icd, err := strconv.ParseInt(v, 10, 8)
		if err != nil {
			return nil, ErrInvalidTXTRecord
		}
		txt.ICDMode = ICDMode(icd)
		txt.ICDSet = true
	}

	// PH
	if v, ok := m[TXTKeyPairingHint]; ok {
		ph, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil, ErrInvalidTXTRecord
		}
		txt.PairingHint = uint16(ph)
	}

	// PI
	if v, ok := m[TXTKeyPairingInstructions]; ok {
		txt.PairingInstructions = v
	}

	return txt, nil
}

// ParseOperationalTXT parses raw TXT records into OperationalTXT.
func ParseOperationalTXT(records []string) (*OperationalTXT, error) {
	m := ParseTXT(records)
	txt := &OperationalTXT{}

	// SII
	if v, ok := m[TXTKeyIdleInterval]; ok {
		sii, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, ErrInvalidTXTRecord
		}
		txt.IdleInterval = time.Duration(sii) * time.Millisecond
	}

	// SAI
	if v, ok := m[TXTKeyActiveInterval]; ok {
		sai, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, ErrInvalidTXTRecord
		}
		txt.ActiveInterval = time.Duration(sai) * time.Millisecond
	}

	// T
	if v, ok := m[TXTKeyTCPSupported]; ok {
		txt.TCPSupported = v == "1"
	}

	// ICD
	if v, ok := m[TXTKeyICDMode]; ok {
		icd, err := strconv.ParseInt(v, 10, 8)
		if err != nil {
			return nil, ErrInvalidTXTRecord
		}
		txt.ICDMode = ICDMode(icd)
		txt.ICDSet = true
	}

	return txt, nil
}

// ParseCommissionerTXT parses raw TXT records into CommissionerTXT.
func ParseCommissionerTXT(records []string) (*CommissionerTXT, error) {
	m := ParseTXT(records)
	txt := &CommissionerTXT{}

	// VP
	if v, ok := m[TXTKeyVendorProduct]; ok {
		if err := parseVendorProduct(v, &txt.VendorID, &txt.ProductID); err != nil {
			return nil, err
		}
	}

	// DT
	if v, ok := m[TXTKeyDeviceType]; ok {
		dt, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, ErrInvalidTXTRecord
		}
		txt.DeviceType = uint32(dt)
	}

	// DN
	if v, ok := m[TXTKeyDeviceName]; ok {
		txt.DeviceName = v
	}

	// CP
	if v, ok := m[TXTKeyCommissionerPasscode]; ok {
		txt.CommissionerPasscode = v == "1"
	}

	return txt, nil
}

// parseVendorProduct parses "VID+PID" format string.
func parseVendorProduct(s string, vid *fabric.VendorID, pid *uint16) error {
	parts := strings.SplitN(s, "+", 2)
	if len(parts) != 2 {
		return ErrInvalidTXTRecord
	}

	v, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return ErrInvalidTXTRecord
	}
	*vid = fabric.VendorID(v)

	p, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return ErrInvalidTXTRecord
	}
	*pid = uint16(p)

	return nil
}
