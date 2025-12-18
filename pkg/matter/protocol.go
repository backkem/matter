package matter

import (
	"github.com/backkem/matter/pkg/exchange"
	"github.com/backkem/matter/pkg/im"
	imsg "github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/message"
	"github.com/backkem/matter/pkg/securechannel"
)

// secureChannelAdapter adapts securechannel.Manager to exchange.ProtocolHandler.
type secureChannelAdapter struct {
	manager *securechannel.Manager
}

// newSecureChannelAdapter creates a new secure channel protocol adapter.
func newSecureChannelAdapter(manager *securechannel.Manager) *secureChannelAdapter {
	return &secureChannelAdapter{manager: manager}
}

// OnMessage handles a message on an existing exchange.
func (a *secureChannelAdapter) OnMessage(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	return a.handleSecureChannel(ctx, opcode, payload)
}

// OnUnsolicited handles a new unsolicited message.
func (a *secureChannelAdapter) OnUnsolicited(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	return a.handleSecureChannel(ctx, opcode, payload)
}

// handleSecureChannel routes secure channel messages and sends response with correct opcode.
func (a *secureChannelAdapter) handleSecureChannel(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	msg := &securechannel.Message{
		Opcode:  securechannel.Opcode(opcode),
		Payload: payload,
	}

	response, err := a.manager.Route(ctx.ID, msg)
	if err != nil {
		return nil, err
	}

	if response == nil {
		return nil, nil
	}

	// Send response with the opcode from the Message
	if err := ctx.SendMessage(uint8(response.Opcode), response.Payload, true); err != nil {
		return nil, err
	}

	// Return nil so exchange manager doesn't send another response
	return nil, nil
}

// Verify secureChannelAdapter implements exchange.ProtocolHandler.
var _ exchange.ProtocolHandler = (*secureChannelAdapter)(nil)

// imAdapter adapts im.Engine to exchange.ProtocolHandler.
type imAdapter struct {
	engine *im.Engine
}

// newIMAdapter creates a new interaction model protocol adapter.
func newIMAdapter(engine *im.Engine) *imAdapter {
	return &imAdapter{engine: engine}
}

// OnMessage handles a message on an existing exchange.
func (a *imAdapter) OnMessage(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	return a.handleIM(ctx, opcode, payload)
}

// OnUnsolicited handles a new unsolicited message.
func (a *imAdapter) OnUnsolicited(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	return a.handleIM(ctx, opcode, payload)
}

// handleIM routes IM messages and handles response opcodes.
func (a *imAdapter) handleIM(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	// Build protocol header for IM
	header := &message.ProtocolHeader{
		ProtocolID:     im.ProtocolID,
		ProtocolOpcode: opcode,
		ExchangeID:     ctx.ID,
	}

	response, err := a.engine.OnMessage(ctx, header, payload)
	if err != nil {
		return nil, err
	}

	if response == nil {
		return nil, nil
	}

	// Compute the correct response opcode based on the request opcode
	responseOpcode := imResponseOpcode(imsg.Opcode(opcode))

	// Send response with the correct opcode directly
	if err := ctx.SendMessage(responseOpcode, response, true); err != nil {
		return nil, err
	}

	// Return nil so exchange manager doesn't send another response
	return nil, nil
}

// imResponseOpcode maps IM request opcodes to response opcodes.
func imResponseOpcode(requestOpcode imsg.Opcode) uint8 {
	switch requestOpcode {
	case imsg.OpcodeReadRequest:
		return uint8(imsg.OpcodeReportData)
	case imsg.OpcodeWriteRequest:
		return uint8(imsg.OpcodeWriteResponse)
	case imsg.OpcodeInvokeRequest:
		return uint8(imsg.OpcodeInvokeResponse)
	case imsg.OpcodeSubscribeRequest:
		return uint8(imsg.OpcodeSubscribeResponse)
	case imsg.OpcodeTimedRequest:
		return uint8(imsg.OpcodeStatusResponse)
	case imsg.OpcodeStatusResponse:
		// StatusResponse typically continues a flow (e.g., after timed request)
		return uint8(requestOpcode)
	default:
		// Default to same opcode
		return uint8(requestOpcode)
	}
}

// Verify imAdapter implements exchange.ProtocolHandler.
var _ exchange.ProtocolHandler = (*imAdapter)(nil)
