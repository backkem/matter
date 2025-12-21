// Package messages provides common encoding utilities for Matter secure channel protocols.
package messages

import "github.com/backkem/matter/pkg/tlv"

// PutSessionID writes a session ID as UInt16.
// Per Matter spec Section 4.11.2, session IDs must always be encoded as 2-byte unsigned integers.
func PutSessionID(w *tlv.Writer, tag tlv.Tag, sessionID uint16) error {
	return w.PutUintWithWidth(tag, uint64(sessionID), 2)
}

// PutPasscodeID writes a passcode ID as UInt16.
// Per Matter spec Section 5.1.6.3, passcode IDs must always be encoded as 2-byte unsigned integers.
func PutPasscodeID(w *tlv.Writer, tag tlv.Tag, passcodeID uint16) error {
	return w.PutUintWithWidth(tag, uint64(passcodeID), 2)
}
