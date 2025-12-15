// Package im implements the Matter Interaction Model.
package im

import (
	"bytes"
	"errors"
	"sync"

	"github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/tlv"
)

// Chunking-related errors.
var (
	ErrChunkingNotInProgress = errors.New("chunking: no assembly in progress")
	ErrChunkingInProgress    = errors.New("chunking: assembly already in progress")
	ErrChunkingPayloadEmpty  = errors.New("chunking: empty payload")
	ErrChunkingMTUTooSmall   = errors.New("chunking: MTU too small for header")
)

// Default MTU values per Matter spec.
const (
	// DefaultMTU is the default IPv6 minimum MTU.
	DefaultMTU = 1280

	// MessageHeaderOverhead is approximate header overhead.
	// This includes message header, protocol header, and encryption overhead.
	MessageHeaderOverhead = 100

	// DefaultMaxPayload is the default maximum payload size per chunk.
	DefaultMaxPayload = DefaultMTU - MessageHeaderOverhead
)

// ChunkType identifies what type of message is being chunked.
type ChunkType int

const (
	ChunkTypeNone ChunkType = iota
	ChunkTypeWriteRequest
	ChunkTypeReportData
	ChunkTypeInvokeResponse
)

// String returns a human-readable name for the chunk type.
func (t ChunkType) String() string {
	switch t {
	case ChunkTypeNone:
		return "None"
	case ChunkTypeWriteRequest:
		return "WriteRequest"
	case ChunkTypeReportData:
		return "ReportData"
	case ChunkTypeInvokeResponse:
		return "InvokeResponse"
	default:
		return "Unknown"
	}
}

// Assembler collects chunked messages until complete.
// It accumulates the array elements from each chunk until
// MoreChunkedMessages is false, then returns the complete message.
//
// Per Spec 10.3.2: When a message is chunked, each chunk contains
// partial array elements. The receiver accumulates these until the
// final chunk (MoreChunkedMessages=false).
type Assembler struct {
	// chunkType is the type of message being assembled.
	chunkType ChunkType

	// accumulated holds the accumulated data from chunks.
	// For writes: accumulated AttributeDataIBs
	// For reports: accumulated AttributeReportIBs and EventReportIBs
	// For invoke responses: accumulated InvokeResponseIBs
	writeRequests   []message.AttributeDataIB
	attributeReports []message.AttributeReportIB
	eventReports     []message.EventReportIB
	invokeResponses  []message.InvokeResponseIB

	// Header fields from the first chunk (preserved across chunks).
	suppressResponse bool
	timedRequest     bool
	subscriptionID   *message.SubscriptionID

	mu sync.Mutex
}

// NewAssembler creates a new chunking assembler.
func NewAssembler() *Assembler {
	return &Assembler{}
}

// Reset clears the assembler state.
func (a *Assembler) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.chunkType = ChunkTypeNone
	a.writeRequests = nil
	a.attributeReports = nil
	a.eventReports = nil
	a.invokeResponses = nil
	a.suppressResponse = false
	a.timedRequest = false
	a.subscriptionID = nil
}

// IsAssembling returns true if assembly is in progress.
func (a *Assembler) IsAssembling() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.chunkType != ChunkTypeNone
}

// ChunkType returns the current chunk type being assembled.
func (a *Assembler) ChunkType() ChunkType {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.chunkType
}

// AddWriteRequest adds a WriteRequestMessage chunk.
// Returns (completeMessage, isComplete, error).
// If isComplete is true, completeMessage contains the assembled message.
func (a *Assembler) AddWriteRequest(msg *message.WriteRequestMessage) (*message.WriteRequestMessage, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Start new assembly or continue existing
	if a.chunkType == ChunkTypeNone {
		a.chunkType = ChunkTypeWriteRequest
		a.suppressResponse = msg.SuppressResponse
		a.timedRequest = msg.TimedRequest
		a.writeRequests = nil
	} else if a.chunkType != ChunkTypeWriteRequest {
		return nil, false, ErrChunkingInProgress
	}

	// Accumulate write requests
	a.writeRequests = append(a.writeRequests, msg.WriteRequests...)

	// Check if complete
	if !msg.MoreChunkedMessages {
		result := &message.WriteRequestMessage{
			SuppressResponse:    a.suppressResponse,
			TimedRequest:        a.timedRequest,
			WriteRequests:       a.writeRequests,
			MoreChunkedMessages: false,
		}

		// Reset state
		a.chunkType = ChunkTypeNone
		a.writeRequests = nil
		a.suppressResponse = false
		a.timedRequest = false

		return result, true, nil
	}

	return nil, false, nil
}

// AddReportData adds a ReportDataMessage chunk.
// Returns (completeMessage, isComplete, error).
func (a *Assembler) AddReportData(msg *message.ReportDataMessage) (*message.ReportDataMessage, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Start new assembly or continue existing
	if a.chunkType == ChunkTypeNone {
		a.chunkType = ChunkTypeReportData
		a.suppressResponse = msg.SuppressResponse
		a.subscriptionID = msg.SubscriptionID
		a.attributeReports = nil
		a.eventReports = nil
	} else if a.chunkType != ChunkTypeReportData {
		return nil, false, ErrChunkingInProgress
	}

	// Accumulate reports
	a.attributeReports = append(a.attributeReports, msg.AttributeReports...)
	a.eventReports = append(a.eventReports, msg.EventReports...)

	// Check if complete
	if !msg.MoreChunkedMessages {
		result := &message.ReportDataMessage{
			SubscriptionID:      a.subscriptionID,
			AttributeReports:    a.attributeReports,
			EventReports:        a.eventReports,
			MoreChunkedMessages: false,
			SuppressResponse:    a.suppressResponse,
		}

		// Reset state
		a.chunkType = ChunkTypeNone
		a.attributeReports = nil
		a.eventReports = nil
		a.suppressResponse = false
		a.subscriptionID = nil

		return result, true, nil
	}

	return nil, false, nil
}

// AddInvokeResponse adds an InvokeResponseMessage chunk.
// Returns (completeMessage, isComplete, error).
func (a *Assembler) AddInvokeResponse(msg *message.InvokeResponseMessage) (*message.InvokeResponseMessage, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Start new assembly or continue existing
	if a.chunkType == ChunkTypeNone {
		a.chunkType = ChunkTypeInvokeResponse
		a.suppressResponse = msg.SuppressResponse
		a.invokeResponses = nil
	} else if a.chunkType != ChunkTypeInvokeResponse {
		return nil, false, ErrChunkingInProgress
	}

	// Accumulate invoke responses
	a.invokeResponses = append(a.invokeResponses, msg.InvokeResponses...)

	// Check if complete
	if !msg.MoreChunkedMessages {
		result := &message.InvokeResponseMessage{
			SuppressResponse:    a.suppressResponse,
			InvokeResponses:     a.invokeResponses,
			MoreChunkedMessages: false,
		}

		// Reset state
		a.chunkType = ChunkTypeNone
		a.invokeResponses = nil
		a.suppressResponse = false

		return result, true, nil
	}

	return nil, false, nil
}

// Fragmenter splits large messages into chunks that fit within MTU.
type Fragmenter struct {
	// maxPayload is the maximum payload size per chunk.
	maxPayload int
}

// NewFragmenter creates a new fragmenter with the given max payload size.
func NewFragmenter(maxPayload int) *Fragmenter {
	if maxPayload <= 0 {
		maxPayload = DefaultMaxPayload
	}
	return &Fragmenter{maxPayload: maxPayload}
}

// FragmentInvokeResponse splits an InvokeResponseMessage into chunks.
// Returns a slice of chunked messages ready for transmission.
func (f *Fragmenter) FragmentInvokeResponse(msg *message.InvokeResponseMessage) ([]*message.InvokeResponseMessage, error) {
	if len(msg.InvokeResponses) == 0 {
		// No chunking needed for empty response
		return []*message.InvokeResponseMessage{msg}, nil
	}

	// Estimate size of each response
	var chunks []*message.InvokeResponseMessage
	var currentChunk []message.InvokeResponseIB
	var currentSize int

	// Base overhead for message structure (structure tags, booleans)
	baseOverhead := 20

	for _, resp := range msg.InvokeResponses {
		// Estimate size of this response
		respSize := estimateInvokeResponseIBSize(&resp)

		// Check if adding this would exceed limit
		if currentSize > 0 && currentSize+respSize+baseOverhead > f.maxPayload {
			// Emit current chunk
			chunk := &message.InvokeResponseMessage{
				SuppressResponse:    msg.SuppressResponse,
				InvokeResponses:     currentChunk,
				MoreChunkedMessages: true,
			}
			chunks = append(chunks, chunk)

			// Start new chunk
			currentChunk = nil
			currentSize = 0
		}

		currentChunk = append(currentChunk, resp)
		currentSize += respSize
	}

	// Emit final chunk
	if len(currentChunk) > 0 {
		chunk := &message.InvokeResponseMessage{
			SuppressResponse:    msg.SuppressResponse,
			InvokeResponses:     currentChunk,
			MoreChunkedMessages: false,
		}
		chunks = append(chunks, chunk)
	}

	return chunks, nil
}

// FragmentWriteRequest splits a WriteRequestMessage into chunks.
func (f *Fragmenter) FragmentWriteRequest(msg *message.WriteRequestMessage) ([]*message.WriteRequestMessage, error) {
	if len(msg.WriteRequests) == 0 {
		return []*message.WriteRequestMessage{msg}, nil
	}

	var chunks []*message.WriteRequestMessage
	var currentChunk []message.AttributeDataIB
	var currentSize int

	baseOverhead := 20

	for _, req := range msg.WriteRequests {
		reqSize := estimateAttributeDataIBSize(&req)

		if currentSize > 0 && currentSize+reqSize+baseOverhead > f.maxPayload {
			chunk := &message.WriteRequestMessage{
				SuppressResponse:    msg.SuppressResponse,
				TimedRequest:        msg.TimedRequest,
				WriteRequests:       currentChunk,
				MoreChunkedMessages: true,
			}
			chunks = append(chunks, chunk)

			currentChunk = nil
			currentSize = 0
		}

		currentChunk = append(currentChunk, req)
		currentSize += reqSize
	}

	if len(currentChunk) > 0 {
		chunk := &message.WriteRequestMessage{
			SuppressResponse:    msg.SuppressResponse,
			TimedRequest:        msg.TimedRequest,
			WriteRequests:       currentChunk,
			MoreChunkedMessages: false,
		}
		chunks = append(chunks, chunk)
	}

	return chunks, nil
}

// FragmentReportData splits a ReportDataMessage into chunks.
func (f *Fragmenter) FragmentReportData(msg *message.ReportDataMessage) ([]*message.ReportDataMessage, error) {
	if len(msg.AttributeReports) == 0 && len(msg.EventReports) == 0 {
		return []*message.ReportDataMessage{msg}, nil
	}

	var chunks []*message.ReportDataMessage
	var currentAttrReports []message.AttributeReportIB
	var currentEventReports []message.EventReportIB
	var currentSize int

	baseOverhead := 30 // More overhead for report data (subscription ID, etc.)

	// Process attribute reports first
	for _, report := range msg.AttributeReports {
		reportSize := estimateAttributeReportIBSize(&report)

		if currentSize > 0 && currentSize+reportSize+baseOverhead > f.maxPayload {
			chunk := &message.ReportDataMessage{
				SubscriptionID:      msg.SubscriptionID,
				AttributeReports:    currentAttrReports,
				EventReports:        currentEventReports,
				MoreChunkedMessages: true,
				SuppressResponse:    false, // Chunked reports need response for flow control
			}
			chunks = append(chunks, chunk)

			currentAttrReports = nil
			currentEventReports = nil
			currentSize = 0
		}

		currentAttrReports = append(currentAttrReports, report)
		currentSize += reportSize
	}

	// Process event reports
	for _, report := range msg.EventReports {
		reportSize := estimateEventReportIBSize(&report)

		if currentSize > 0 && currentSize+reportSize+baseOverhead > f.maxPayload {
			chunk := &message.ReportDataMessage{
				SubscriptionID:      msg.SubscriptionID,
				AttributeReports:    currentAttrReports,
				EventReports:        currentEventReports,
				MoreChunkedMessages: true,
				SuppressResponse:    false,
			}
			chunks = append(chunks, chunk)

			currentAttrReports = nil
			currentEventReports = nil
			currentSize = 0
		}

		currentEventReports = append(currentEventReports, report)
		currentSize += reportSize
	}

	// Emit final chunk
	if len(currentAttrReports) > 0 || len(currentEventReports) > 0 {
		chunk := &message.ReportDataMessage{
			SubscriptionID:      msg.SubscriptionID,
			AttributeReports:    currentAttrReports,
			EventReports:        currentEventReports,
			MoreChunkedMessages: false,
			SuppressResponse:    msg.SuppressResponse,
		}
		chunks = append(chunks, chunk)
	}

	return chunks, nil
}

// NeedsChunking returns true if the message exceeds the MTU.
func (f *Fragmenter) NeedsChunking(data []byte) bool {
	return len(data) > f.maxPayload
}

// Size estimation functions
// These provide rough estimates for chunking decisions.

func estimateInvokeResponseIBSize(ib *message.InvokeResponseIB) int {
	size := 10 // Base structure overhead
	if ib.Command != nil {
		size += estimateCommandDataIBSize(ib.Command)
	}
	if ib.Status != nil {
		size += 20 // CommandStatusIB
	}
	return size
}

func estimateCommandDataIBSize(ib *message.CommandDataIB) int {
	size := 15 // Path overhead
	size += len(ib.Fields)
	return size
}

func estimateAttributeDataIBSize(ib *message.AttributeDataIB) int {
	size := 20 // Path and version overhead
	size += len(ib.Data)
	return size
}

func estimateAttributeReportIBSize(ib *message.AttributeReportIB) int {
	size := 5 // Structure overhead
	if ib.AttributeData != nil {
		size += estimateAttributeDataIBSize(ib.AttributeData)
	}
	if ib.AttributeStatus != nil {
		size += 25 // AttributeStatusIB
	}
	return size
}

func estimateEventReportIBSize(ib *message.EventReportIB) int {
	size := 5 // Structure overhead
	if ib.EventData != nil {
		size += 30 // Path and metadata
		size += len(ib.EventData.Data)
	}
	if ib.EventStatus != nil {
		size += 25 // EventStatusIB
	}
	return size
}

// EncodeMessage encodes a message to TLV bytes.
// This is a helper for estimating actual encoded size.
func EncodeMessage(encode func(w *tlv.Writer) error) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := encode(w); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
