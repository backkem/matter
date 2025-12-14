package securechannel

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// StatusReport message sizes.
const (
	// StatusReportMinSize is the minimum size of a StatusReport (no ProtocolData).
	StatusReportMinSize = 8 // GeneralCode(2) + ProtocolID(4) + ProtocolCode(2)
)

// Errors
var (
	ErrStatusReportTooShort = errors.New("securechannel: status report too short")
)

// StatusReport encapsulates the data in a StatusReport message.
//
// See Matter Specification Appendix D.
type StatusReport struct {
	GeneralCode  GeneralCode
	ProtocolID   uint32 // VendorID (upper 16) | ProtocolID (lower 16)
	ProtocolCode uint16
	ProtocolData []byte // Optional protocol-specific data
}

// NewStatusReport creates a StatusReport with no protocol data.
func NewStatusReport(general GeneralCode, protocolID uint32, code uint16) *StatusReport {
	return &StatusReport{
		GeneralCode:  general,
		ProtocolID:   protocolID,
		ProtocolCode: code,
	}
}

// NewSecureChannelStatusReport creates a StatusReport for the Secure Channel protocol.
func NewSecureChannelStatusReport(general GeneralCode, code ProtocolCode) *StatusReport {
	return &StatusReport{
		GeneralCode:  general,
		ProtocolID:   uint32(ProtocolID), // VendorID=0, ProtocolID=0
		ProtocolCode: uint16(code),
	}
}

// Success creates a success StatusReport for session establishment.
func Success() *StatusReport {
	return NewSecureChannelStatusReport(GeneralCodeSuccess, ProtocolCodeSuccess)
}

// InvalidParam creates an invalid parameter StatusReport.
func InvalidParam() *StatusReport {
	return NewSecureChannelStatusReport(GeneralCodeFailure, ProtocolCodeInvalidParam)
}

// Busy creates a busy StatusReport with the minimum wait time in milliseconds.
func Busy(waitTimeMs uint16) *StatusReport {
	data := make([]byte, 2)
	binary.LittleEndian.PutUint16(data, waitTimeMs)
	return &StatusReport{
		GeneralCode:  GeneralCodeBusy,
		ProtocolID:   uint32(ProtocolID),
		ProtocolCode: uint16(ProtocolCodeBusy),
		ProtocolData: data,
	}
}

// CloseSession creates a close session StatusReport.
func CloseSession() *StatusReport {
	return NewSecureChannelStatusReport(GeneralCodeSuccess, ProtocolCodeCloseSession)
}

// Encode serializes the StatusReport to bytes.
func (s *StatusReport) Encode() []byte {
	size := StatusReportMinSize + len(s.ProtocolData)
	buf := make([]byte, size)

	binary.LittleEndian.PutUint16(buf[0:2], uint16(s.GeneralCode))
	binary.LittleEndian.PutUint32(buf[2:6], s.ProtocolID)
	binary.LittleEndian.PutUint16(buf[6:8], s.ProtocolCode)

	if len(s.ProtocolData) > 0 {
		copy(buf[8:], s.ProtocolData)
	}

	return buf
}

// DecodeStatusReport parses a StatusReport from bytes.
func DecodeStatusReport(data []byte) (*StatusReport, error) {
	if len(data) < StatusReportMinSize {
		return nil, ErrStatusReportTooShort
	}

	s := &StatusReport{
		GeneralCode:  GeneralCode(binary.LittleEndian.Uint16(data[0:2])),
		ProtocolID:   binary.LittleEndian.Uint32(data[2:6]),
		ProtocolCode: binary.LittleEndian.Uint16(data[6:8]),
	}

	if len(data) > StatusReportMinSize {
		s.ProtocolData = make([]byte, len(data)-StatusReportMinSize)
		copy(s.ProtocolData, data[StatusReportMinSize:])
	}

	return s, nil
}

// IsSuccess returns true if this is a success status.
func (s *StatusReport) IsSuccess() bool {
	return s.GeneralCode == GeneralCodeSuccess
}

// IsBusy returns true if this is a busy status.
func (s *StatusReport) IsBusy() bool {
	return s.GeneralCode == GeneralCodeBusy &&
		s.ProtocolID == uint32(ProtocolID) &&
		s.ProtocolCode == uint16(ProtocolCodeBusy)
}

// BusyWaitTime returns the minimum wait time in milliseconds if this is a busy status.
// Returns 0 if not a busy status or if protocol data is missing.
func (s *StatusReport) BusyWaitTime() uint16 {
	if !s.IsBusy() || len(s.ProtocolData) < 2 {
		return 0
	}
	return binary.LittleEndian.Uint16(s.ProtocolData)
}

// IsSecureChannel returns true if this status is for the Secure Channel protocol.
func (s *StatusReport) IsSecureChannel() bool {
	return s.ProtocolID == uint32(ProtocolID)
}

// SecureChannelCode returns the ProtocolCode as a SecureChannel ProtocolCode.
// Only valid if IsSecureChannel() returns true.
func (s *StatusReport) SecureChannelCode() ProtocolCode {
	return ProtocolCode(s.ProtocolCode)
}

// String returns a human-readable representation.
func (s *StatusReport) String() string {
	if s.IsSecureChannel() {
		return fmt.Sprintf("StatusReport{General: %s, Protocol: SecureChannel, Code: %s}",
			s.GeneralCode, ProtocolCode(s.ProtocolCode))
	}
	return fmt.Sprintf("StatusReport{General: %s, ProtocolID: 0x%08X, Code: 0x%04X}",
		s.GeneralCode, s.ProtocolID, s.ProtocolCode)
}

// Error implements the error interface for StatusReport.
func (s *StatusReport) Error() string {
	return s.String()
}
