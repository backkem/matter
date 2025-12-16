package matter

import (
	"github.com/backkem/matter/pkg/exchange"
	"github.com/backkem/matter/pkg/im"
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
	return a.manager.Route(ctx.ID, securechannel.Opcode(opcode), payload)
}

// OnUnsolicited handles a new unsolicited message.
func (a *secureChannelAdapter) OnUnsolicited(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	return a.manager.Route(ctx.ID, securechannel.Opcode(opcode), payload)
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
	// Build protocol header for IM
	header := &message.ProtocolHeader{
		ProtocolID:     im.ProtocolID,
		ProtocolOpcode: opcode,
		ExchangeID:     ctx.ID,
	}

	return a.engine.OnMessage(ctx, header, payload)
}

// OnUnsolicited handles a new unsolicited message.
func (a *imAdapter) OnUnsolicited(ctx *exchange.ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	// Build protocol header for IM
	header := &message.ProtocolHeader{
		ProtocolID:     im.ProtocolID,
		ProtocolOpcode: opcode,
		ExchangeID:     ctx.ID,
	}

	return a.engine.OnMessage(ctx, header, payload)
}

// Verify imAdapter implements exchange.ProtocolHandler.
var _ exchange.ProtocolHandler = (*imAdapter)(nil)
