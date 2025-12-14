package message

import (
	"encoding/binary"
	"io"
)

// Frame represents a complete Matter message frame.
// For unencrypted messages, all fields are accessible.
// For encrypted messages, the payload contains encrypted ProtocolHeader + Application Payload.
type Frame struct {
	Header   MessageHeader
	Protocol ProtocolHeader
	Payload  []byte // Application payload (after protocol header)
}

// EncodeUnsecured encodes the frame for an unsecured session (no encryption).
// Used during session establishment (PASE/CASE handshake).
func (f *Frame) EncodeUnsecured() []byte {
	headerSize := f.Header.Size()
	protocolSize := f.Protocol.Size()
	totalSize := headerSize + protocolSize + len(f.Payload)

	buf := make([]byte, totalSize)
	offset := f.Header.EncodeTo(buf)
	offset += f.Protocol.EncodeTo(buf[offset:])
	copy(buf[offset:], f.Payload)

	return buf
}

// DecodeUnsecured decodes an unsecured message frame.
// Returns an error if the message is malformed.
func DecodeUnsecured(data []byte) (*Frame, error) {
	f := &Frame{}

	// Decode message header
	headerLen, err := f.Header.Decode(data)
	if err != nil {
		return nil, err
	}

	// For unsecured messages, decode protocol header from payload
	payloadStart := headerLen
	if len(data) < payloadStart {
		return nil, ErrMessageTooShort
	}

	protocolLen, err := f.Protocol.Decode(data[payloadStart:])
	if err != nil {
		return nil, err
	}

	// Remaining data is application payload
	appPayloadStart := payloadStart + protocolLen
	if len(data) > appPayloadStart {
		f.Payload = make([]byte, len(data)-appPayloadStart)
		copy(f.Payload, data[appPayloadStart:])
	}

	return f, nil
}

// RawFrame represents a raw message frame with encrypted payload.
// Used for handling messages before decryption or after encryption.
type RawFrame struct {
	Header           MessageHeader
	EncryptedPayload []byte // Protocol header + payload (encrypted)
	MIC              []byte // Message Integrity Check (16 bytes)
}

// EncodeRaw encodes the raw frame to wire format.
func (r *RawFrame) EncodeRaw() []byte {
	headerSize := r.Header.Size()
	totalSize := headerSize + len(r.EncryptedPayload) + len(r.MIC)

	buf := make([]byte, totalSize)
	offset := r.Header.EncodeTo(buf)
	offset += copy(buf[offset:], r.EncryptedPayload)
	copy(buf[offset:], r.MIC)

	return buf
}

// DecodeRaw decodes a raw message frame from wire data.
// The payload remains encrypted; use SecureCodec to decrypt.
func DecodeRaw(data []byte) (*RawFrame, error) {
	r := &RawFrame{}

	// Decode message header
	headerLen, err := r.Header.Decode(data)
	if err != nil {
		return nil, err
	}

	// For secure messages, extract encrypted payload and MIC
	if r.Header.IsSecure() {
		// Need at least MIC bytes after header
		if len(data) < headerLen+MICSize {
			return nil, ErrMessageTooShort
		}

		payloadEnd := len(data) - MICSize
		r.EncryptedPayload = make([]byte, payloadEnd-headerLen)
		copy(r.EncryptedPayload, data[headerLen:payloadEnd])

		r.MIC = make([]byte, MICSize)
		copy(r.MIC, data[payloadEnd:])
	} else {
		// Unsecured message has no MIC
		if len(data) > headerLen {
			r.EncryptedPayload = make([]byte, len(data)-headerLen)
			copy(r.EncryptedPayload, data[headerLen:])
		}
	}

	return r, nil
}

// TotalSize returns the total wire size of the raw frame.
func (r *RawFrame) TotalSize() int {
	size := r.Header.Size() + len(r.EncryptedPayload)
	if r.Header.IsSecure() {
		size += MICSize
	}
	return size
}

// StreamWriter wraps an io.Writer to add TCP length-prefix framing.
type StreamWriter struct {
	w io.Writer
}

// NewStreamWriter creates a new stream writer for TCP framing.
func NewStreamWriter(w io.Writer) *StreamWriter {
	return &StreamWriter{w: w}
}

// Write writes a message with a 4-byte little-endian length prefix.
func (sw *StreamWriter) Write(frame []byte) (int, error) {
	// Write 4-byte length prefix
	var lenBuf [TCPLengthPrefixSize]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(frame)))

	n, err := sw.w.Write(lenBuf[:])
	if err != nil {
		return n, err
	}

	// Write frame data
	m, err := sw.w.Write(frame)
	return n + m, err
}

// WriteFrame encodes and writes a raw frame with length prefix.
func (sw *StreamWriter) WriteFrame(frame *RawFrame) error {
	data := frame.EncodeRaw()
	_, err := sw.Write(data)
	return err
}

// StreamReader wraps an io.Reader to read TCP length-prefixed frames.
type StreamReader struct {
	r io.Reader
}

// NewStreamReader creates a new stream reader for TCP framing.
func NewStreamReader(r io.Reader) *StreamReader {
	return &StreamReader{r: r}
}

// Read reads a length-prefixed message from the stream.
// Returns the frame data without the length prefix.
func (sr *StreamReader) Read() ([]byte, error) {
	// Read 4-byte length prefix
	var lenBuf [TCPLengthPrefixSize]byte
	if _, err := io.ReadFull(sr.r, lenBuf[:]); err != nil {
		if err == io.EOF {
			return nil, err
		}
		return nil, ErrStreamReadFailed
	}

	frameLen := binary.LittleEndian.Uint32(lenBuf[:])

	// Sanity check on length
	if frameLen == 0 {
		return nil, ErrInvalidLengthPrefix
	}
	if frameLen > MaxUDPMessageSize*2 { // Allow larger for TCP
		return nil, ErrMessageTooLong
	}

	// Read frame data
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(sr.r, frame); err != nil {
		return nil, ErrStreamReadFailed
	}

	return frame, nil
}

// ReadFrame reads and decodes a raw frame from the stream.
func (sr *StreamReader) ReadFrame() (*RawFrame, error) {
	data, err := sr.Read()
	if err != nil {
		return nil, err
	}
	return DecodeRaw(data)
}

// EncodeWithLengthPrefix adds a 4-byte length prefix to frame data.
// Used for TCP transport.
func EncodeWithLengthPrefix(frame []byte) []byte {
	buf := make([]byte, TCPLengthPrefixSize+len(frame))
	binary.LittleEndian.PutUint32(buf[:TCPLengthPrefixSize], uint32(len(frame)))
	copy(buf[TCPLengthPrefixSize:], frame)
	return buf
}

// ValidateSize checks if the frame size is within UDP MTU limits.
func ValidateSize(data []byte) error {
	if len(data) > MaxUDPMessageSize {
		return ErrMessageTooLong
	}
	return nil
}
