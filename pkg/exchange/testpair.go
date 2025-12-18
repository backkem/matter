package exchange

import (
	"sync"
	"time"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/message"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
)

// =============================================================================
// Exported Test Infrastructure for E2E Testing
// =============================================================================

// TestManagerPair provides two connected exchange.Manager instances for E2E testing.
// Messages sent from one manager are delivered to the other through the full stack:
// exchange.Manager -> transport -> pipe -> transport -> exchange.Manager -> ProtocolHandler
//
// Usage:
//
//	pair, _ := exchange.NewTestManagerPair(exchange.TestManagerPairConfig{UDP: true})
//	defer pair.Close()
//
//	// Register your protocol handler
//	pair.Manager(1).RegisterProtocol(myProtocolID, myHandler)
//
//	// Create exchange and send message from manager 0 to manager 1
//	exch, _ := pair.Manager(0).NewExchange(pair.Session(0), 0, pair.PeerAddress(1, false), myProtocolID, myDelegate)
//	exch.SendMessage(opcode, payload, true)
type TestManagerPair struct {
	managers       [2]*Manager
	sessions       [2]*TestUnsecuredSession
	sessionMgrs    [2]*session.Manager
	handlers       [2]*TestProtocolHandler
	transportPair  *transport.PipeManagerPair
	received       [2]chan ReceivedMessage
	handlerWrapper [2]*exchangeHandlerWrapper
}

// ReceivedMessage represents a message received by a test manager.
type ReceivedMessage struct {
	Opcode      uint8
	Payload     []byte
	ExchangeID  uint16
	Unsolicited bool
}

// TestManagerPairConfig configures the test manager pair.
type TestManagerPairConfig struct {
	// UDP enables UDP transport (default: true if neither set)
	UDP bool
	// TCP enables TCP transport
	TCP bool
}

// exchangeHandlerWrapper routes transport messages to exchange manager.
type exchangeHandlerWrapper struct {
	manager *Manager
}

func (w *exchangeHandlerWrapper) Handle(msg *transport.ReceivedMessage) {
	if w.manager != nil {
		w.manager.OnMessageReceived(msg)
	}
}

// NewTestManagerPair creates two exchange managers connected via virtual pipe.
func NewTestManagerPair(config TestManagerPairConfig) (*TestManagerPair, error) {
	// Default to UDP if neither specified
	if !config.UDP && !config.TCP {
		config.UDP = true
	}

	pair := &TestManagerPair{
		received: [2]chan ReceivedMessage{
			make(chan ReceivedMessage, 100),
			make(chan ReceivedMessage, 100),
		},
	}

	// Create handler wrappers
	pair.handlerWrapper[0] = &exchangeHandlerWrapper{}
	pair.handlerWrapper[1] = &exchangeHandlerWrapper{}

	// Create transport pair
	transportPair, err := transport.NewPipeManagerPair(transport.PipeManagerConfig{
		UDP: config.UDP,
		TCP: config.TCP,
		Handlers: [2]transport.MessageHandler{
			pair.handlerWrapper[0].Handle,
			pair.handlerWrapper[1].Handle,
		},
	})
	if err != nil {
		return nil, err
	}
	pair.transportPair = transportPair

	// Create protocol handlers
	for i := 0; i < 2; i++ {
		idx := i
		pair.handlers[i] = &TestProtocolHandler{}
		pair.handlers[i].onReceive = func(msg ReceivedMessage) {
			select {
			case pair.received[idx] <- msg:
			default:
			}
		}
	}

	// Create session managers
	pair.sessionMgrs[0] = session.NewManager(session.ManagerConfig{})
	pair.sessionMgrs[1] = session.NewManager(session.ManagerConfig{})

	// Create sessions: node IDs 0x1000 for side 0, 0x2000 for side 1
	pair.sessions[0] = NewTestUnsecuredSession(0x1000)
	pair.sessions[1] = NewTestUnsecuredSession(0x2000)

	// Create exchange managers
	for i := 0; i < 2; i++ {
		pair.managers[i] = NewManager(ManagerConfig{
			SessionManager:   pair.sessionMgrs[i],
			TransportManager: transportPair.Manager(i),
		})
		pair.handlerWrapper[i].manager = pair.managers[i]
		pair.managers[i].RegisterProtocol(message.ProtocolSecureChannel, pair.handlers[i])
	}

	return pair, nil
}

// Manager returns the exchange manager at the given index (0 or 1).
func (p *TestManagerPair) Manager(idx int) *Manager {
	return p.managers[idx]
}

// Session returns the test session for the given index.
func (p *TestManagerPair) Session(idx int) *TestUnsecuredSession {
	return p.sessions[idx]
}

// PeerAddress returns the peer address for sending to the given index.
// Use PeerAddress(1, false) when sending FROM manager 0 TO manager 1.
func (p *TestManagerPair) PeerAddress(idx int, tcp bool) transport.PeerAddress {
	addrs := p.transportPair.PeerAddresses(idx)
	if tcp {
		return addrs.TCP
	}
	return addrs.UDP
}

// WaitForMessage waits for a message to be received by the specified manager.
func (p *TestManagerPair) WaitForMessage(idx int, timeout time.Duration) (ReceivedMessage, bool) {
	select {
	case msg := <-p.received[idx]:
		return msg, true
	case <-time.After(timeout):
		return ReceivedMessage{}, false
	}
}

// Pipe returns the underlying pipe for network simulation.
func (p *TestManagerPair) Pipe() *transport.Pipe {
	return p.transportPair.Pipe()
}

// SessionManager returns the session manager at the given index.
func (p *TestManagerPair) SessionManager(idx int) *session.Manager {
	return p.sessionMgrs[idx]
}

// Close cleans up all resources.
func (p *TestManagerPair) Close() {
	for i := 0; i < 2; i++ {
		if p.managers[i] != nil {
			p.managers[i].Close()
		}
	}
	if p.transportPair != nil {
		p.transportPair.Close()
	}
}

// TestUnsecuredSession creates unsecured messages (session ID 0) with source node ID.
type TestUnsecuredSession struct {
	params       session.Params
	sourceNodeID fabric.NodeID
	counter      uint32
	mu           sync.Mutex
}

// NewTestUnsecuredSession creates a new test unsecured session.
func NewTestUnsecuredSession(sourceNodeID uint64) *TestUnsecuredSession {
	return &TestUnsecuredSession{
		params: session.Params{
			IdleInterval:    50 * time.Millisecond,
			ActiveInterval:  30 * time.Millisecond,
			ActiveThreshold: 100 * time.Millisecond,
		},
		sourceNodeID: fabric.NodeID(sourceNodeID),
	}
}

// GetParams implements session.Context.
func (s *TestUnsecuredSession) GetParams() session.Params {
	return s.params
}

// LocalSessionID implements session.Context.
func (s *TestUnsecuredSession) LocalSessionID() uint16 {
	return 0
}

// PeerSessionID implements session.Context.
func (s *TestUnsecuredSession) PeerSessionID() uint16 {
	return 0
}

// IsPeerActive implements session.Context.
func (s *TestUnsecuredSession) IsPeerActive() bool {
	return false
}

// Encrypt implements session.Context.
func (s *TestUnsecuredSession) Encrypt(header *message.MessageHeader, protocol *message.ProtocolHeader, payload []byte, privacy bool) ([]byte, error) {
	s.mu.Lock()
	s.counter++
	header.MessageCounter = s.counter
	s.mu.Unlock()

	header.SessionID = 0
	header.SourcePresent = true
	header.SourceNodeID = uint64(s.sourceNodeID)

	frame := &message.Frame{
		Header:   *header,
		Protocol: *protocol,
		Payload:  payload,
	}
	return frame.EncodeUnsecured(), nil
}

// TestProtocolHandler records messages and notifies via callback.
type TestProtocolHandler struct {
	messages  []testMessage
	onReceive func(ReceivedMessage)
	mu        sync.Mutex
}

type testMessage struct {
	ExchangeID  uint16
	Opcode      uint8
	Payload     []byte
	Unsolicited bool
}

// OnMessage implements ProtocolHandler.
func (h *TestProtocolHandler) OnMessage(ctx *ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	msg := testMessage{
		ExchangeID: ctx.ID,
		Opcode:     opcode,
		Payload:    append([]byte(nil), payload...),
	}
	h.messages = append(h.messages, msg)

	if h.onReceive != nil {
		h.onReceive(ReceivedMessage{
			Opcode:     opcode,
			Payload:    msg.Payload,
			ExchangeID: ctx.ID,
		})
	}
	return nil, nil
}

// OnUnsolicited implements ProtocolHandler.
func (h *TestProtocolHandler) OnUnsolicited(ctx *ExchangeContext, opcode uint8, payload []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	msg := testMessage{
		ExchangeID:  ctx.ID,
		Opcode:      opcode,
		Payload:     append([]byte(nil), payload...),
		Unsolicited: true,
	}
	h.messages = append(h.messages, msg)

	if h.onReceive != nil {
		h.onReceive(ReceivedMessage{
			Opcode:      opcode,
			Payload:     msg.Payload,
			ExchangeID:  ctx.ID,
			Unsolicited: true,
		})
	}
	return nil, nil
}
