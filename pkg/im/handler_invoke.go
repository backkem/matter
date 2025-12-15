package im

import (
	"bytes"
	"errors"
	"sync"

	"github.com/backkem/matter/pkg/exchange"
	"github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/tlv"
)

// InvokeHandler errors.
var (
	ErrInvokeHandlerBusy       = errors.New("invoke handler: busy processing another request")
	ErrInvokeTimedMismatch     = errors.New("invoke handler: timed request mismatch")
	ErrInvokeCommandNotFound   = errors.New("invoke handler: command not found")
	ErrInvokeInvalidPath       = errors.New("invoke handler: invalid command path")
)

// CommandHandler is called to process an invoke request.
// It receives the command path and raw TLV command fields,
// and returns response data (raw TLV) or an error status.
type CommandHandler func(
	ctx *InvokeContext,
	path message.CommandPathIB,
	fields []byte,
) (*CommandResult, error)

// CommandResult is the result of a command invocation.
type CommandResult struct {
	// ResponsePath is the command path for the response.
	// Typically the same as the request path for server commands.
	ResponsePath message.CommandPathIB

	// ResponseData is the TLV-encoded response data.
	// nil if command has no response data.
	ResponseData []byte

	// Status is set if the command failed with a status instead of response.
	Status *message.StatusIB
}

// InvokeContext provides context for command invocation.
type InvokeContext struct {
	// Exchange is the underlying exchange context.
	Exchange *exchange.ExchangeContext

	// FabricIndex is the accessing fabric (0 if none).
	FabricIndex uint8

	// IsTimed indicates if this is part of a timed interaction.
	IsTimed bool

	// SourceNodeID is the requesting node.
	SourceNodeID uint64
}

// InvokeHandlerState represents the handler state machine.
type InvokeHandlerState int

const (
	InvokeHandlerStateIdle InvokeHandlerState = iota
	InvokeHandlerStateReceiving
	InvokeHandlerStateProcessing
	InvokeHandlerStateSendingResponse
)

// String returns the state name.
func (s InvokeHandlerState) String() string {
	switch s {
	case InvokeHandlerStateIdle:
		return "Idle"
	case InvokeHandlerStateReceiving:
		return "Receiving"
	case InvokeHandlerStateProcessing:
		return "Processing"
	case InvokeHandlerStateSendingResponse:
		return "SendingResponse"
	default:
		return "Unknown"
	}
}

// InvokeHandler handles invoke request messages.
// It supports chunked requests and responses for large payloads.
type InvokeHandler struct {
	// commandHandler is called to process commands.
	commandHandler CommandHandler

	// chunking support
	assembler   *Assembler
	fragmenter  *Fragmenter

	// State
	state       InvokeHandlerState
	ctx         *InvokeContext

	// Pending response chunks
	pendingChunks []*message.InvokeResponseMessage
	chunkIndex    int

	mu sync.Mutex
}

// NewInvokeHandler creates a new invoke handler.
func NewInvokeHandler(handler CommandHandler, maxPayload int) *InvokeHandler {
	return &InvokeHandler{
		commandHandler: handler,
		assembler:      NewAssembler(),
		fragmenter:     NewFragmenter(maxPayload),
		state:          InvokeHandlerStateIdle,
	}
}

// HandleInvokeRequest processes an incoming InvokeRequestMessage.
// Returns the response message (or nil for chunked flow control).
func (h *InvokeHandler) HandleInvokeRequest(
	exchCtx *exchange.ExchangeContext,
	msg *message.InvokeRequestMessage,
	fabricIndex uint8,
	sourceNodeID uint64,
	isTimed bool,
) (*message.InvokeResponseMessage, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Validate timed request flag
	if msg.TimedRequest && !isTimed {
		return nil, ErrInvokeTimedMismatch
	}

	// Create invoke context
	h.ctx = &InvokeContext{
		Exchange:     exchCtx,
		FabricIndex:  fabricIndex,
		IsTimed:      isTimed,
		SourceNodeID: sourceNodeID,
	}

	// Note: Per Matter spec, InvokeRequestMessage does NOT support chunking
	// in the current specification version. The MoreChunkedMessages field
	// exists only in InvokeResponseMessage.
	// See: "NOTE In this version of the specification, InvokeRequestMessage
	// contains no provisions for spanning multiple messages"

	// Process all commands in the request
	h.state = InvokeHandlerStateProcessing

	responses, err := h.processCommands(msg)
	if err != nil {
		h.state = InvokeHandlerStateIdle
		return nil, err
	}

	// Build response message
	response := &message.InvokeResponseMessage{
		SuppressResponse: msg.SuppressResponse,
		InvokeResponses:  responses,
	}

	// Check if response needs chunking
	chunks, err := h.fragmenter.FragmentInvokeResponse(response)
	if err != nil {
		h.state = InvokeHandlerStateIdle
		return nil, err
	}

	if len(chunks) == 1 {
		// No chunking needed
		h.state = InvokeHandlerStateIdle
		return chunks[0], nil
	}

	// Chunked response - store chunks and return first
	h.state = InvokeHandlerStateSendingResponse
	h.pendingChunks = chunks
	h.chunkIndex = 1 // First chunk (index 0) returned now

	return chunks[0], nil
}

// HandleStatusResponse processes a StatusResponse during chunked transmission.
// Returns the next response chunk, or nil if transmission is complete.
func (h *InvokeHandler) HandleStatusResponse(status message.Status) (*message.InvokeResponseMessage, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.state != InvokeHandlerStateSendingResponse {
		return nil, nil // Not in chunking mode
	}

	if status != message.StatusSuccess {
		// Peer rejected - abort chunking
		h.state = InvokeHandlerStateIdle
		h.pendingChunks = nil
		return nil, nil
	}

	// Send next chunk
	if h.chunkIndex >= len(h.pendingChunks) {
		// All chunks sent
		h.state = InvokeHandlerStateIdle
		h.pendingChunks = nil
		return nil, nil
	}

	chunk := h.pendingChunks[h.chunkIndex]
	h.chunkIndex++

	// Check if this was the last chunk
	if h.chunkIndex >= len(h.pendingChunks) {
		h.state = InvokeHandlerStateIdle
		h.pendingChunks = nil
	}

	return chunk, nil
}

// processCommands invokes all commands in the request.
func (h *InvokeHandler) processCommands(msg *message.InvokeRequestMessage) ([]message.InvokeResponseIB, error) {
	var responses []message.InvokeResponseIB

	for i, cmdData := range msg.InvokeRequests {
		response, err := h.invokeCommand(&cmdData)
		if err != nil {
			// Create error response for this command
			response = h.createErrorResponse(&cmdData, message.StatusFailure)
		}

		// Set CommandRef if present in request (for batch correlation)
		if cmdData.Ref != nil {
			if response.Command != nil {
				response.Command.Ref = cmdData.Ref
			}
			if response.Status != nil {
				ref := *cmdData.Ref
				response.Status.Ref = &ref
			}
		} else if len(msg.InvokeRequests) > 1 {
			// Multiple commands require CommandRef per spec
			// Use index as implicit ref
			ref := uint16(i)
			if response.Command != nil {
				response.Command.Ref = &ref
			}
			if response.Status != nil {
				response.Status.Ref = &ref
			}
		}

		responses = append(responses, response)
	}

	return responses, nil
}

// invokeCommand calls the command handler for a single command.
func (h *InvokeHandler) invokeCommand(cmdData *message.CommandDataIB) (message.InvokeResponseIB, error) {
	if h.commandHandler == nil {
		return h.createErrorResponse(cmdData, message.StatusUnsupportedCommand), nil
	}

	result, err := h.commandHandler(h.ctx, cmdData.Path, cmdData.Fields)
	if err != nil {
		return h.createErrorResponse(cmdData, message.StatusFailure), nil
	}

	if result == nil {
		// No response (command with no response data)
		return h.createSuccessResponse(cmdData), nil
	}

	if result.Status != nil {
		// Command returned a status
		return message.InvokeResponseIB{
			Status: &message.CommandStatusIB{
				Path:   cmdData.Path,
				Status: *result.Status,
			},
		}, nil
	}

	// Command returned response data
	return message.InvokeResponseIB{
		Command: &message.CommandDataIB{
			Path:   result.ResponsePath,
			Fields: result.ResponseData,
		},
	}, nil
}

// createErrorResponse creates an error response for a command.
func (h *InvokeHandler) createErrorResponse(cmdData *message.CommandDataIB, status message.Status) message.InvokeResponseIB {
	return message.InvokeResponseIB{
		Status: &message.CommandStatusIB{
			Path: cmdData.Path,
			Status: message.StatusIB{
				Status: status,
			},
		},
	}
}

// createSuccessResponse creates a success response for a command.
func (h *InvokeHandler) createSuccessResponse(cmdData *message.CommandDataIB) message.InvokeResponseIB {
	return message.InvokeResponseIB{
		Status: &message.CommandStatusIB{
			Path: cmdData.Path,
			Status: message.StatusIB{
				Status: message.StatusSuccess,
			},
		},
	}
}

// Reset resets the handler to idle state.
func (h *InvokeHandler) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.state = InvokeHandlerStateIdle
	h.ctx = nil
	h.pendingChunks = nil
	h.chunkIndex = 0
	h.assembler.Reset()
}

// State returns the current handler state.
func (h *InvokeHandler) State() InvokeHandlerState {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// EncodeStatusResponse encodes a status response message.
func EncodeStatusResponse(status message.Status) ([]byte, error) {
	msg := message.StatusResponseMessage{Status: status}
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := msg.Encode(w); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EncodeInvokeResponse encodes an invoke response message.
func EncodeInvokeResponse(msg *message.InvokeResponseMessage) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := msg.Encode(w); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeInvokeRequest decodes an invoke request message.
func DecodeInvokeRequest(data []byte) (*message.InvokeRequestMessage, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	var msg message.InvokeRequestMessage
	if err := msg.Decode(r); err != nil {
		return nil, err
	}
	return &msg, nil
}

// DecodeStatusResponse decodes a status response message.
func DecodeStatusResponse(data []byte) (*message.StatusResponseMessage, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	var msg message.StatusResponseMessage
	if err := msg.Decode(r); err != nil {
		return nil, err
	}
	return &msg, nil
}
