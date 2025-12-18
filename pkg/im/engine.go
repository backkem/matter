package im

import (
	"bytes"
	"sync"

	"github.com/backkem/matter/pkg/acl"
	"github.com/backkem/matter/pkg/exchange"
	imsg "github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/message"
	"github.com/backkem/matter/pkg/tlv"
	"github.com/pion/logging"
)

// ProtocolID is the Interaction Model protocol ID.
// Spec: Section 10.2.1
const ProtocolID message.ProtocolID = 0x0001

// Engine is the Interaction Model engine.
// It implements exchange.ExchangeDelegate for the IM protocol.
//
// This simplified engine supports:
//   - ReadRequest → ReportData
//   - WriteRequest → WriteResponse
//   - InvokeRequest → InvokeResponse
//   - StatusResponse (for chunked flows)
//
// It does NOT support (for commissioning simplicity):
//   - Subscriptions
//   - Timed interactions
//   - Complex chunking
//
// Spec Reference: Chapter 8 "Interaction Model Specification"
// C++ Reference: src/app/InteractionModelEngine.cpp
type Engine struct {
	// dispatcher routes operations to clusters
	dispatcher Dispatcher

	// aclChecker performs access control checks (optional)
	aclChecker *acl.Checker

	// Handlers (pooled for reuse)
	readHandler   *ReadHandler
	writeHandler  *WriteHandler
	invokeHandler *InvokeHandler

	// maxPayload for chunked responses
	maxPayload int

	log logging.LeveledLogger

	mu sync.Mutex
}

// EngineConfig configures the Engine.
type EngineConfig struct {
	// Dispatcher routes operations to cluster implementations.
	// Required.
	Dispatcher Dispatcher

	// ACLChecker performs access control checks.
	// Optional - if nil, ACL checks are skipped.
	ACLChecker *acl.Checker

	// MaxPayload is the maximum payload size for responses.
	// Defaults to DefaultMaxPayload if 0.
	MaxPayload int

	// LoggerFactory is the factory for creating loggers.
	// If nil, logging is disabled.
	LoggerFactory logging.LoggerFactory
}

// NewEngine creates a new IM engine.
func NewEngine(config EngineConfig) *Engine {
	maxPayload := config.MaxPayload
	if maxPayload == 0 {
		maxPayload = DefaultMaxPayload
	}

	dispatcher := config.Dispatcher
	if dispatcher == nil {
		dispatcher = NullDispatcher{}
	}

	e := &Engine{
		dispatcher:    dispatcher,
		aclChecker:    config.ACLChecker,
		maxPayload:    maxPayload,
		readHandler:   NewReadHandler(nil, maxPayload),   // Reader set per-request
		writeHandler:  NewWriteHandler(dispatcher),
		invokeHandler: NewInvokeHandler(nil, maxPayload), // Handler set per-request
	}

	if config.LoggerFactory != nil {
		e.log = config.LoggerFactory.NewLogger("im")
	}

	return e
}

// OnMessage implements exchange.ExchangeDelegate.
// This is the main entry point for IM messages.
//
// The engine sends responses directly via ctx.SendMessage with the correct
// response opcode (matching the C++ SDK architecture), then returns (nil, nil)
// so the exchange layer doesn't send again.
//
// Spec: 8.2.4 "Action" - defines valid opcodes
// C++ Reference: InteractionModelEngine::OnMessageReceived
func (e *Engine) OnMessage(
	ctx *exchange.ExchangeContext,
	header *message.ProtocolHeader,
	payload []byte,
) ([]byte, error) {
	opcode := imsg.Opcode(header.ProtocolOpcode)

	var responsePayload []byte
	var responseOpcode imsg.Opcode
	var err error

	switch opcode {
	case imsg.OpcodeReadRequest:
		responsePayload, err = e.handleReadRequest(ctx, payload)
		responseOpcode = imsg.OpcodeReportData

	case imsg.OpcodeWriteRequest:
		responsePayload, err = e.handleWriteRequest(ctx, payload)
		responseOpcode = imsg.OpcodeWriteResponse

	case imsg.OpcodeInvokeRequest:
		responsePayload, err = e.handleInvokeRequest(ctx, payload)
		responseOpcode = imsg.OpcodeInvokeResponse

	case imsg.OpcodeStatusResponse:
		// StatusResponse handling may return different response types
		return e.handleStatusResponse(ctx, payload)

	case imsg.OpcodeSubscribeRequest:
		// Not implemented in simplified engine
		responsePayload, _ = e.encodeStatusResponse(imsg.StatusUnsupportedAccess)
		responseOpcode = imsg.OpcodeStatusResponse

	case imsg.OpcodeTimedRequest:
		// Not implemented in simplified engine
		responsePayload, _ = e.encodeStatusResponse(imsg.StatusUnsupportedAccess)
		responseOpcode = imsg.OpcodeStatusResponse

	default:
		responsePayload, _ = e.encodeStatusResponse(imsg.StatusInvalidAction)
		responseOpcode = imsg.OpcodeStatusResponse
	}

	if err != nil {
		return nil, err
	}

	// No response to send (e.g., SuppressResponse was set)
	if responsePayload == nil {
		return nil, nil
	}

	// If context is nil (unit tests), return payload directly for verification
	if ctx == nil {
		return responsePayload, nil
	}

	// Send response directly with correct opcode
	// C++ Reference: CommandResponseSender::SendCommandResponse calls
	// mExchangeCtx->SendMessage(MsgType::InvokeCommandResponse, ...)
	if sendErr := ctx.SendMessage(uint8(responseOpcode), responsePayload, true); sendErr != nil {
		return nil, sendErr
	}

	// Return nil so exchange layer doesn't send again
	return nil, nil
}

// OnClose implements exchange.ExchangeDelegate.
func (e *Engine) OnClose(ctx *exchange.ExchangeContext) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Reset handlers if they were active on this exchange
	e.readHandler.Reset()
	e.writeHandler.Reset()
	e.invokeHandler.Reset()
}

// handleReadRequest processes a ReadRequestMessage.
func (e *Engine) handleReadRequest(ctx *exchange.ExchangeContext, payload []byte) ([]byte, error) {
	// Decode request
	req, err := DecodeReadRequest(payload)
	if err != nil {
		return e.encodeStatusResponse(imsg.StatusInvalidAction)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Create attribute reader that uses dispatcher
	reader := e.createAttributeReader()

	// Create handler with reader
	handler := NewReadHandler(reader, e.maxPayload)

	// Extract fabric/node info from session (simplified - would come from SecureContext)
	fabricIndex := uint8(1)   // TODO: extract from session
	sourceNodeID := uint64(0) // TODO: extract from session

	// Process request
	resp, err := handler.HandleReadRequest(ctx, req, fabricIndex, sourceNodeID)
	if err != nil {
		return e.encodeStatusResponse(ErrorToStatus(err))
	}

	// Store handler for potential chunked continuation
	e.readHandler = handler

	return EncodeReportData(resp)
}

// handleWriteRequest processes a WriteRequestMessage.
func (e *Engine) handleWriteRequest(ctx *exchange.ExchangeContext, payload []byte) ([]byte, error) {
	// Decode request
	req, err := DecodeWriteRequest(payload)
	if err != nil {
		return e.encodeStatusResponse(imsg.StatusInvalidAction)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Extract fabric/node info from session (simplified)
	fabricIndex := uint8(1)
	sourceNodeID := uint64(0)
	isTimed := false // Timed interactions not supported in simplified engine

	// Process request
	resp, err := e.writeHandler.HandleWriteRequest(ctx, req, fabricIndex, sourceNodeID, isTimed)
	if err != nil {
		return e.encodeStatusResponse(ErrorToStatus(err))
	}

	// If SuppressResponse was set, resp is nil
	if resp == nil {
		return nil, nil
	}

	return EncodeWriteResponse(resp)
}

// handleInvokeRequest processes an InvokeRequestMessage.
func (e *Engine) handleInvokeRequest(ctx *exchange.ExchangeContext, payload []byte) ([]byte, error) {
	// Decode request
	req, err := DecodeInvokeRequest(payload)
	if err != nil {
		return e.encodeStatusResponse(imsg.StatusInvalidAction)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Create command handler that uses dispatcher
	cmdHandler := e.createCommandHandler()

	// Create handler
	handler := NewInvokeHandler(cmdHandler, e.maxPayload)

	// Extract fabric/node info from session (simplified)
	fabricIndex := uint8(1)
	sourceNodeID := uint64(0)
	isTimed := false

	// Process request
	resp, err := handler.HandleInvokeRequest(ctx, req, fabricIndex, sourceNodeID, isTimed)
	if err != nil {
		return e.encodeStatusResponse(ErrorToStatus(err))
	}

	// Store handler for potential chunked continuation
	e.invokeHandler = handler

	return EncodeInvokeResponse(resp)
}

// handleStatusResponse processes a StatusResponseMessage.
// Used for chunked response flow control.
// This method sends responses directly with correct opcodes.
func (e *Engine) handleStatusResponse(ctx *exchange.ExchangeContext, payload []byte) ([]byte, error) {
	// Decode status
	statusMsg, err := DecodeStatusResponse(payload)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if read handler has pending chunks
	if e.readHandler.State() == ReadHandlerStateSendingReport {
		resp, err := e.readHandler.HandleStatusResponse(statusMsg.Status)
		if err != nil {
			responsePayload, _ := e.encodeStatusResponse(ErrorToStatus(err))
			return e.sendOrReturn(ctx, uint8(imsg.OpcodeStatusResponse), responsePayload)
		}
		if resp != nil {
			responsePayload, err := EncodeReportData(resp)
			if err != nil {
				return nil, err
			}
			return e.sendOrReturn(ctx, uint8(imsg.OpcodeReportData), responsePayload)
		}
		return nil, nil
	}

	// Check if invoke handler has pending chunks
	if e.invokeHandler.State() == InvokeHandlerStateSendingResponse {
		resp, err := e.invokeHandler.HandleStatusResponse(statusMsg.Status)
		if err != nil {
			responsePayload, _ := e.encodeStatusResponse(ErrorToStatus(err))
			return e.sendOrReturn(ctx, uint8(imsg.OpcodeStatusResponse), responsePayload)
		}
		if resp != nil {
			responsePayload, err := EncodeInvokeResponse(resp)
			if err != nil {
				return nil, err
			}
			return e.sendOrReturn(ctx, uint8(imsg.OpcodeInvokeResponse), responsePayload)
		}
		return nil, nil
	}

	// No handler expecting status response
	return nil, nil
}

// sendOrReturn either sends via exchange context or returns payload for unit tests.
func (e *Engine) sendOrReturn(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	if ctx == nil {
		return payload, nil
	}
	if err := ctx.SendMessage(opcode, payload, true); err != nil {
		return nil, err
	}
	return nil, nil
}

// createAttributeReader creates an AttributeReader that uses the dispatcher.
func (e *Engine) createAttributeReader() AttributeReader {
	return func(ctx *ReadContext, path imsg.AttributePathIB) (*AttributeResult, error) {
		req := &AttributeReadRequest{
			Path:             path,
			IsFabricFiltered: ctx.IsFabricFiltered,
		}

		var buf bytes.Buffer
		w := tlv.NewWriter(&buf)

		err := e.dispatcher.ReadAttribute(nil, req, w)
		if err != nil {
			return &AttributeResult{
				Status: &imsg.StatusIB{
					Status: ErrorToStatus(err),
				},
			}, nil
		}

		return &AttributeResult{
			DataVersion: 1, // TODO: get from cluster
			Data:        buf.Bytes(),
		}, nil
	}
}

// createCommandHandler creates a CommandHandler that uses the dispatcher.
func (e *Engine) createCommandHandler() CommandHandler {
	return func(ctx *InvokeContext, path imsg.CommandPathIB, fields []byte) (*CommandResult, error) {
		req := &CommandInvokeRequest{
			Path:    path,
			IsTimed: ctx.IsTimed,
		}

		r := tlv.NewReader(bytes.NewReader(fields))

		respData, err := e.dispatcher.InvokeCommand(nil, req, r)
		if err != nil {
			return &CommandResult{
				Status: &imsg.StatusIB{
					Status: ErrorToStatus(err),
				},
			}, nil
		}

		return &CommandResult{
			ResponsePath: path,
			ResponseData: respData,
		}, nil
	}
}

// encodeStatusResponse encodes a status response message.
func (e *Engine) encodeStatusResponse(status imsg.Status) ([]byte, error) {
	return EncodeStatusResponse(status)
}

// GetProtocolID returns the protocol ID for registration with ExchangeManager.
func (e *Engine) GetProtocolID() message.ProtocolID {
	return ProtocolID
}
