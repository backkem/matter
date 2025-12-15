package im

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"github.com/backkem/matter/pkg/exchange"
	"github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/tlv"
)

// WriteHandler errors.
var (
	ErrWriteHandlerBusy    = errors.New("write handler: busy processing another request")
	ErrWriteTimedMismatch  = errors.New("write handler: timed request mismatch")
	ErrWriteWildcardPath   = errors.New("write handler: wildcard paths not supported")
	ErrWriteListOperation  = errors.New("write handler: list operations not supported")
)

// WriteHandlerState represents the handler state machine.
// Spec: 8.7 Write Interaction
type WriteHandlerState int

const (
	WriteHandlerStateIdle WriteHandlerState = iota
	WriteHandlerStateProcessing
	WriteHandlerStateReceivingChunks
	WriteHandlerStateSendingResponse
)

// String returns the state name.
func (s WriteHandlerState) String() string {
	switch s {
	case WriteHandlerStateIdle:
		return "Idle"
	case WriteHandlerStateProcessing:
		return "Processing"
	case WriteHandlerStateReceivingChunks:
		return "ReceivingChunks"
	case WriteHandlerStateSendingResponse:
		return "SendingResponse"
	default:
		return "Unknown"
	}
}

// WriteContext provides context for attribute writes.
type WriteContext struct {
	// Exchange is the underlying exchange context.
	Exchange *exchange.ExchangeContext

	// FabricIndex is the accessing fabric (0 if none).
	FabricIndex uint8

	// IsTimed indicates if this is part of a timed interaction.
	IsTimed bool

	// SourceNodeID is the requesting node.
	SourceNodeID uint64
}

// WriteHandler handles write request messages.
// This is a simplified implementation for commissioning use cases.
// It does NOT support:
//   - Wildcard paths (concrete paths only)
//   - Chunked write requests (single message only)
//   - List operations (Add/Remove - only full Replace)
//
// For full IM spec compliance, see docs/pkgs/im-plan.md.
//
// Spec Reference: Section 8.7 "Write Interaction"
// C++ Reference: src/app/WriteHandler.cpp
type WriteHandler struct {
	// dispatcher routes write operations to clusters.
	dispatcher Dispatcher

	// State
	state WriteHandlerState
	ctx   *WriteContext

	// Pending response statuses
	writeStatuses []message.AttributeStatusIB

	// Suppress response flag from request
	suppressResponse bool

	mu sync.Mutex
}

// NewWriteHandler creates a new write handler.
func NewWriteHandler(dispatcher Dispatcher) *WriteHandler {
	if dispatcher == nil {
		dispatcher = NullDispatcher{}
	}
	return &WriteHandler{
		dispatcher: dispatcher,
		state:      WriteHandlerStateIdle,
	}
}

// HandleWriteRequest processes an incoming WriteRequestMessage.
// Returns the WriteResponseMessage.
//
// Spec: 8.7.3.2 "Outgoing Write Response Action" (server-side processing)
func (h *WriteHandler) HandleWriteRequest(
	exchCtx *exchange.ExchangeContext,
	msg *message.WriteRequestMessage,
	fabricIndex uint8,
	sourceNodeID uint64,
	isTimed bool,
) (*message.WriteResponseMessage, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Validate timed request flag
	// Spec 8.7.2.3: TimedRequest field must match actual timed interaction state
	if msg.TimedRequest && !isTimed {
		return nil, ErrWriteTimedMismatch
	}

	// Create write context
	h.ctx = &WriteContext{
		Exchange:     exchCtx,
		FabricIndex:  fabricIndex,
		IsTimed:      isTimed,
		SourceNodeID: sourceNodeID,
	}

	h.state = WriteHandlerStateProcessing
	h.suppressResponse = msg.SuppressResponse
	h.writeStatuses = nil

	// Note: This simplified implementation does NOT support MoreChunkedMessages.
	// For commissioning, writes are small enough to fit in a single message.
	if msg.MoreChunkedMessages {
		h.state = WriteHandlerStateIdle
		return nil, ErrWriteListOperation // Chunked writes typically involve lists
	}

	// Process all attribute data IBs in the request
	for _, attrData := range msg.WriteRequests {
		status := h.processAttributeWrite(&attrData)
		h.writeStatuses = append(h.writeStatuses, status)
	}

	// Build response
	h.state = WriteHandlerStateIdle

	// If SuppressResponse is set, return nil (no response sent)
	// Spec 8.7.2.3: "If SuppressResponse is true, no response shall be generated"
	if msg.SuppressResponse {
		return nil, nil
	}

	return &message.WriteResponseMessage{
		WriteResponses: h.writeStatuses,
	}, nil
}

// processAttributeWrite processes a single attribute write.
// Returns an AttributeStatusIB for the response.
//
// Spec: 8.7.3.2 step-by-step processing
func (h *WriteHandler) processAttributeWrite(attrData *message.AttributeDataIB) message.AttributeStatusIB {
	path := attrData.Path

	// Step 1: Validate path - wildcards not allowed in writes
	// Spec 8.7.3.2: "Writes SHALL NOT use wildcard paths"
	if isWildcardAttributePath(&path) {
		return h.createWriteStatusResponse(&path, message.StatusInvalidAction)
	}

	// Step 2: Check for list operations (ListIndex present)
	// Simplified implementation: we only support full attribute replacement
	if path.ListIndex != nil {
		return h.createWriteStatusResponse(&path, message.StatusUnsupportedWrite)
	}

	// Step 3: Build write request for dispatcher
	writeReq := &AttributeWriteRequest{
		Path:      path,
		IMContext: nil, // Would be set from h.ctx in full implementation
		IsTimed:   h.ctx.IsTimed,
	}

	// DataVersion is optional - only set if non-zero
	if attrData.DataVersion != 0 {
		dv := attrData.DataVersion
		writeReq.DataVersion = &dv
	}

	// Step 4: Dispatch to cluster via dispatcher
	// The dispatcher handles ACL checks and routing to the correct cluster
	r := tlv.NewReader(bytes.NewReader(attrData.Data))
	err := h.dispatcher.WriteAttribute(context.Background(), writeReq, r)

	if err != nil {
		return h.createWriteStatusResponse(&path, ErrorToStatus(err))
	}

	return h.createWriteStatusResponse(&path, message.StatusSuccess)
}

// createWriteStatusResponse creates an AttributeStatusIB for the response.
func (h *WriteHandler) createWriteStatusResponse(path *message.AttributePathIB, status message.Status) message.AttributeStatusIB {
	return message.AttributeStatusIB{
		Path: *path,
		Status: message.StatusIB{
			Status: status,
		},
	}
}

// isWildcardAttributePath checks if the path contains wildcards.
func isWildcardAttributePath(path *message.AttributePathIB) bool {
	// Per spec, wildcards are indicated by omitted fields (nil pointers)
	// For writes, all of Endpoint, Cluster, and Attribute must be present
	return path.Endpoint == nil || path.Cluster == nil || path.Attribute == nil
}

// Reset resets the handler to idle state.
func (h *WriteHandler) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.state = WriteHandlerStateIdle
	h.ctx = nil
	h.writeStatuses = nil
	h.suppressResponse = false
}

// State returns the current handler state.
func (h *WriteHandler) State() WriteHandlerState {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// EncodeWriteResponse encodes a write response message.
func EncodeWriteResponse(msg *message.WriteResponseMessage) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := msg.Encode(w); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeWriteRequest decodes a write request message.
func DecodeWriteRequest(data []byte) (*message.WriteRequestMessage, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	var msg message.WriteRequestMessage
	if err := msg.Decode(r); err != nil {
		return nil, err
	}
	return &msg, nil
}
