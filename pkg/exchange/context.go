package exchange

import (
	"sync"

	"github.com/backkem/matter/pkg/message"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
)

// SessionContext abstracts session.SecureContext and session.UnsecuredContext.
// Both types implement GetParams() which is needed for MRP timing.
type SessionContext interface {
	// GetParams returns the MRP timing parameters for this session.
	GetParams() session.Params
}

// SecureSessionContext extends SessionContext with encryption capabilities.
// Used for type assertion when we need to encrypt/decrypt.
type SecureSessionContext interface {
	SessionContext

	// LocalSessionID returns the local session identifier.
	LocalSessionID() uint16

	// PeerSessionID returns the peer's session identifier.
	PeerSessionID() uint16

	// IsPeerActive returns whether the peer is in active mode for MRP timing.
	IsPeerActive() bool

	// Encrypt encrypts a message for transmission.
	Encrypt(header *message.MessageHeader, protocol *message.ProtocolHeader, payload []byte, privacy bool) ([]byte, error)
}

// ExchangeDelegate receives messages for an exchange from upper layers.
type ExchangeDelegate interface {
	// OnMessage is called when a message is received on this exchange.
	// The exchange context, protocol header, and payload are provided.
	// Returns response payload (if any) and error.
	OnMessage(ctx *ExchangeContext, header *message.ProtocolHeader, payload []byte) ([]byte, error)

	// OnClose is called when the exchange is closed.
	OnClose(ctx *ExchangeContext)
}

// ExchangeContext represents a single conversation (exchange) between nodes.
// Per Spec Section 4.10.3, an exchange context tracks:
//   - Exchange ID: Assigned by initiator
//   - Exchange Role: Initiator or Responder
//   - Session Context: The underlying session
//
// Additionally tracks MRP state per Spec 4.12.3:
//   - One pending acknowledgement per exchange
//   - One pending retransmission per exchange
type ExchangeContext struct {
	// ID is the Exchange ID for this conversation.
	// Assigned by initiator, shared by both parties.
	ID uint16

	// Role indicates if we are initiator or responder.
	Role ExchangeRole

	// State is the current lifecycle state.
	State ExchangeState

	// ProtocolID is the protocol for this exchange (set from first message).
	ProtocolID message.ProtocolID

	// localSessionID is the session ID for routing incoming messages.
	localSessionID uint16

	// session is the underlying session context.
	// Can be *session.SecureContext or *session.UnsecuredContext.
	session SessionContext

	// peerAddress is the destination for sending messages.
	peerAddress transport.PeerAddress

	// delegate receives messages from upper layer.
	delegate ExchangeDelegate

	// manager is the parent manager (for sending, MRP tables).
	manager *Manager

	// pendingAckCounter is the message counter awaiting ACK send (0 if none).
	pendingAckCounter uint32
	hasPendingAck     bool

	// pendingRetransmitCounter is the counter of our message awaiting ACK (0 if none).
	pendingRetransmitCounter uint32
	hasPendingRetransmit     bool

	mu sync.Mutex
}

// ExchangeContextConfig is used to create a new exchange context.
type ExchangeContextConfig struct {
	ID             uint16
	Role           ExchangeRole
	ProtocolID     message.ProtocolID
	LocalSessionID uint16
	Session        SessionContext
	PeerAddress    transport.PeerAddress
	Delegate       ExchangeDelegate
	Manager        *Manager
}

// NewExchangeContext creates a new exchange context.
func NewExchangeContext(config ExchangeContextConfig) *ExchangeContext {
	return &ExchangeContext{
		ID:             config.ID,
		Role:           config.Role,
		State:          ExchangeStateActive,
		ProtocolID:     config.ProtocolID,
		localSessionID: config.LocalSessionID,
		session:        config.Session,
		peerAddress:    config.PeerAddress,
		delegate:       config.Delegate,
		manager:        config.Manager,
	}
}

// GetKey returns the exchange key for table lookups.
func (c *ExchangeContext) GetKey() exchangeKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	return exchangeKey{
		localSessionID: c.localSessionID,
		exchangeID:     c.ID,
		role:           c.Role,
	}
}

// Session returns the underlying session context.
func (c *ExchangeContext) Session() SessionContext {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// PeerAddress returns the peer's network address.
func (c *ExchangeContext) PeerAddress() transport.PeerAddress {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerAddress
}

// LocalSessionID returns the local session ID.
func (c *ExchangeContext) LocalSessionID() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localSessionID
}

// IsInitiator returns true if we are the exchange initiator.
func (c *ExchangeContext) IsInitiator() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Role == ExchangeRoleInitiator
}

// IsClosed returns true if the exchange is closed.
func (c *ExchangeContext) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.State == ExchangeStateClosed
}

// SetDelegate sets the message delegate.
func (c *ExchangeContext) SetDelegate(delegate ExchangeDelegate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.delegate = delegate
}

// GetDelegate returns the current delegate.
func (c *ExchangeContext) GetDelegate() ExchangeDelegate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.delegate
}

// SetPendingAck marks that we need to send an ACK for the given counter.
func (c *ExchangeContext) SetPendingAck(counter uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pendingAckCounter = counter
	c.hasPendingAck = true
}

// ClearPendingAck clears the pending ACK.
func (c *ExchangeContext) ClearPendingAck() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pendingAckCounter = 0
	c.hasPendingAck = false
}

// GetPendingAck returns the pending ACK counter if any.
func (c *ExchangeContext) GetPendingAck() (uint32, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pendingAckCounter, c.hasPendingAck
}

// SetPendingRetransmit marks that we have a message awaiting ACK.
func (c *ExchangeContext) SetPendingRetransmit(counter uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pendingRetransmitCounter = counter
	c.hasPendingRetransmit = true
}

// ClearPendingRetransmit clears the pending retransmit.
func (c *ExchangeContext) ClearPendingRetransmit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pendingRetransmitCounter = 0
	c.hasPendingRetransmit = false
}

// HasPendingRetransmit returns true if we have a message awaiting ACK.
func (c *ExchangeContext) HasPendingRetransmit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hasPendingRetransmit
}

// CanSend returns true if new messages can be sent.
// Per Spec 4.10: Cannot send when closing or when reliable message pending.
func (c *ExchangeContext) CanSend() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.State.CanSend() && !c.hasPendingRetransmit
}

// SendMessage sends a message on this exchange.
// The protocol header's exchange fields will be filled in automatically.
// If reliable is true and transport is UDP, MRP will track the message.
//
// Returns error if exchange is closing/closed or has pending retransmit.
func (c *ExchangeContext) SendMessage(opcode uint8, payload []byte, reliable bool) error {
	c.mu.Lock()
	if !c.State.CanSend() {
		c.mu.Unlock()
		if c.State == ExchangeStateClosed {
			return ErrExchangeClosed
		}
		return ErrExchangeClosing
	}
	if c.hasPendingRetransmit {
		c.mu.Unlock()
		return ErrPendingRetransmit
	}

	manager := c.manager
	c.mu.Unlock()

	if manager == nil {
		return ErrExchangeClosed
	}

	// Build protocol header
	proto := &message.ProtocolHeader{
		ProtocolID:     c.ProtocolID,
		ProtocolOpcode: opcode,
		ExchangeID:     c.ID,
		Initiator:      c.Role == ExchangeRoleInitiator,
		Reliability:    reliable && c.peerAddress.TransportType == transport.TransportTypeUDP,
	}

	// Check for pending ACK to piggyback
	if ackCounter, hasAck := c.GetPendingAck(); hasAck {
		proto.Acknowledgement = true
		proto.AckedMessageCounter = ackCounter
		// Clear pending ACK since we're piggybacking it
		c.ClearPendingAck()
	}

	return manager.sendMessage(c, proto, payload)
}

// Close initiates exchange closure.
// Per Spec 4.10.5.3:
//  1. Flush pending acknowledgements (send standalone ACK if needed)
//  2. Wait for pending retransmissions to complete
//  3. Remove exchange
func (c *ExchangeContext) Close() error {
	c.mu.Lock()
	if c.State == ExchangeStateClosed {
		c.mu.Unlock()
		return nil
	}

	c.State = ExchangeStateClosing
	manager := c.manager
	hasPendingRetransmit := c.hasPendingRetransmit
	c.mu.Unlock()

	if manager == nil {
		return nil
	}

	// Flush pending ACK
	manager.flushPendingAck(c)

	// If no pending retransmit, close immediately
	if !hasPendingRetransmit {
		c.mu.Lock()
		c.State = ExchangeStateClosed
		c.mu.Unlock()

		manager.removeExchange(c)
	}
	// Otherwise, exchange will be removed when retransmit completes/fails

	return nil
}

// onRetransmitComplete is called when retransmission completes (ACK or max retries).
// If exchange is closing, this will finalize the close.
func (c *ExchangeContext) onRetransmitComplete() {
	c.mu.Lock()
	c.hasPendingRetransmit = false
	c.pendingRetransmitCounter = 0

	if c.State == ExchangeStateClosing {
		c.State = ExchangeStateClosed
		manager := c.manager
		c.mu.Unlock()

		if manager != nil {
			manager.removeExchange(c)
		}
		return
	}
	c.mu.Unlock()
}

// HasDelegate returns true if this exchange has a delegate set.
func (c *ExchangeContext) HasDelegate() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.delegate != nil
}

// handleMessage processes an incoming message on this exchange.
// Called by Manager after MRP processing.
func (c *ExchangeContext) handleMessage(proto *message.ProtocolHeader, payload []byte) ([]byte, error) {
	c.mu.Lock()
	if !c.State.CanReceive() {
		c.mu.Unlock()
		return nil, ErrExchangeClosed
	}

	delegate := c.delegate
	c.mu.Unlock()

	if delegate == nil {
		return nil, nil
	}

	return delegate.OnMessage(c, proto, payload)
}
