package exchange

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	"github.com/backkem/matter/pkg/fabric"
	"github.com/backkem/matter/pkg/message"
	"github.com/backkem/matter/pkg/securechannel"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
)

// ProtocolHandler handles messages for a specific protocol.
// Register handlers with Manager.RegisterProtocol().
type ProtocolHandler interface {
	// OnMessage handles a message on an existing exchange.
	// Returns response payload (if any) and error.
	OnMessage(ctx *ExchangeContext, opcode uint8, payload []byte) ([]byte, error)

	// OnUnsolicited handles a new unsolicited message (first message creating an exchange).
	// Returns response payload (if any) and error.
	OnUnsolicited(ctx *ExchangeContext, opcode uint8, payload []byte) ([]byte, error)
}

// ManagerConfig configures the exchange Manager.
type ManagerConfig struct {
	// SessionManager manages session contexts.
	SessionManager *session.Manager

	// TransportManager handles network I/O.
	TransportManager *transport.Manager
}

// Manager coordinates message exchanges and MRP.
// It routes messages between transport/session layers and protocol handlers.
type Manager struct {
	config ManagerConfig

	// exchanges maps {sessionID, exchangeID, role} to exchange context.
	exchanges map[exchangeKey]*ExchangeContext

	// handlers maps protocol ID to handler.
	handlers map[message.ProtocolID]ProtocolHandler

	// ackTable tracks pending ACKs for received reliable messages.
	ackTable *AckTable

	// retransmitTable tracks pending retransmissions.
	retransmitTable *RetransmitTable

	// nextExchangeID is the next exchange ID to allocate (for initiator).
	// Per Spec 4.10.2: First is random, subsequent increment by 1.
	nextExchangeID uint16

	mu sync.RWMutex
}

// NewManager creates a new exchange manager.
func NewManager(config ManagerConfig) *Manager {
	m := &Manager{
		config:          config,
		exchanges:       make(map[exchangeKey]*ExchangeContext),
		handlers:        make(map[message.ProtocolID]ProtocolHandler),
		ackTable:        NewAckTable(),
		retransmitTable: NewRetransmitTable(),
	}

	// Initialize with random exchange ID
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err == nil {
		m.nextExchangeID = binary.LittleEndian.Uint16(buf[:])
	}

	return m
}

// RegisterProtocol registers a handler for a protocol ID.
func (m *Manager) RegisterProtocol(protocolID message.ProtocolID, handler ProtocolHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[protocolID] = handler
}

// NewExchange creates a new exchange as initiator.
// Returns a new ExchangeContext ready for sending the first message.
func (m *Manager) NewExchange(
	sess SessionContext,
	localSessionID uint16,
	peerAddress transport.PeerAddress,
	protocolID message.ProtocolID,
	delegate ExchangeDelegate,
) (*ExchangeContext, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Allocate exchange ID
	exchangeID := m.nextExchangeID
	m.nextExchangeID++

	key := exchangeKey{
		localSessionID: localSessionID,
		exchangeID:     exchangeID,
		role:           ExchangeRoleInitiator,
	}

	// Check for collision (unlikely but possible after 65536 exchanges)
	if _, exists := m.exchanges[key]; exists {
		return nil, ErrExchangeExists
	}

	ctx := NewExchangeContext(ExchangeContextConfig{
		ID:             exchangeID,
		Role:           ExchangeRoleInitiator,
		ProtocolID:     protocolID,
		LocalSessionID: localSessionID,
		Session:        sess,
		PeerAddress:    peerAddress,
		Delegate:       delegate,
		Manager:        m,
	})

	m.exchanges[key] = ctx
	return ctx, nil
}

// OnMessageReceived processes an incoming message from transport.
// This is the main entry point for the receive path.
//
// Flow:
//  1. Parse message header, look up session
//  2. Decrypt if secure session
//  3. Process MRP flags (A flag: handle ACK, R flag: schedule ACK)
//  4. Match to existing exchange or create new one
//  5. Dispatch to protocol handler
func (m *Manager) OnMessageReceived(msg *transport.ReceivedMessage) error {
	// Parse message header to get session ID
	var header message.MessageHeader
	_, err := header.Decode(msg.Data)
	if err != nil {
		return ErrInvalidMessage
	}

	// Look up session
	var sess SessionContext
	var frame *message.Frame

	if header.SessionID == 0 {
		// Unsecured session (handshake phase)
		// For unsecured, we parse the protocol header directly
		frame, err = message.DecodeUnsecured(msg.Data)
		if err != nil {
			return ErrInvalidMessage
		}

		// Per Spec 4.13.2.1: Look up or create UnsecuredContext by source node ID
		// Source must be present for unsecured messages
		if !header.SourcePresent {
			return ErrInvalidMessage
		}

		sourceNodeID := fabric.NodeID(header.SourceNodeID)
		unsecuredCtx, err := m.config.SessionManager.FindOrCreateUnsecuredContext(sourceNodeID)
		if err != nil {
			return err
		}

		// Check message counter for replay
		if !unsecuredCtx.CheckCounter(header.MessageCounter) {
			return ErrInvalidMessage
		}

		sess = unsecuredCtx
	} else {
		// Secure session - decrypt
		secureCtx := m.config.SessionManager.FindSecureContext(header.SessionID)
		if secureCtx == nil {
			return ErrSessionNotFound
		}
		sess = secureCtx

		frame, err = secureCtx.Decrypt(msg.Data)
		if err != nil {
			return err
		}
	}

	return m.processFrame(frame, msg.PeerAddr, sess)
}

// processFrame handles a decoded frame.
func (m *Manager) processFrame(frame *message.Frame, peerAddr transport.PeerAddress, sess SessionContext) error {
	proto := &frame.Protocol

	// Determine our role: if I flag set, sender is initiator, we are responder
	var ourRole ExchangeRole
	if proto.Initiator {
		ourRole = ExchangeRoleResponder
	} else {
		ourRole = ExchangeRoleInitiator
	}

	// Get local session ID for key
	localSessionID := frame.Header.SessionID

	key := exchangeKey{
		localSessionID: localSessionID,
		exchangeID:     proto.ExchangeID,
		role:           ourRole,
	}

	// Process A flag (received ACK)
	if proto.Acknowledgement {
		m.handleReceivedAck(proto.AckedMessageCounter)
	}

	// Match to existing exchange
	m.mu.RLock()
	ctx, exists := m.exchanges[key]
	m.mu.RUnlock()

	if !exists {
		// Unsolicited message
		return m.handleUnsolicited(frame, peerAddr, sess, key)
	}

	// Process R flag (need to send ACK)
	if proto.Reliability {
		m.scheduleAck(ctx, frame.Header.MessageCounter)
	}

	// Dispatch to exchange
	response, err := ctx.handleMessage(proto, frame.Payload)
	if err != nil {
		return err
	}

	// Send response if any
	if response != nil {
		// Determine if response should be reliable
		// Typically responses are reliable for request-response patterns
		reliable := peerAddr.TransportType == transport.TransportTypeUDP
		return ctx.SendMessage(proto.ProtocolOpcode, response, reliable)
	}

	return nil
}

// handleUnsolicited processes a message that doesn't match an existing exchange.
func (m *Manager) handleUnsolicited(
	frame *message.Frame,
	peerAddr transport.PeerAddress,
	sess SessionContext,
	key exchangeKey,
) error {
	proto := frame.Protocol

	// Per Spec 4.10.5.2:
	// 1. If I flag set + registered protocol → create exchange
	// 2. If R flag set → send standalone ACK, drop
	// 3. Otherwise → drop

	if !proto.Initiator {
		// Not from initiator - check if needs ACK
		if proto.Reliability {
			m.sendStandaloneAckForUnsolicited(frame, peerAddr, sess)
		}
		return ErrUnsolicitedNotInitiator
	}

	// Check for registered protocol handler
	m.mu.RLock()
	handler, hasHandler := m.handlers[proto.ProtocolID]
	m.mu.RUnlock()

	if !hasHandler {
		// No handler - send ACK if requested, then drop
		if proto.Reliability {
			m.sendStandaloneAckForUnsolicited(frame, peerAddr, sess)
		}
		return ErrNoHandler
	}

	// Create new exchange as responder
	localSessionID := frame.Header.SessionID

	ctx := NewExchangeContext(ExchangeContextConfig{
		ID:             proto.ExchangeID,
		Role:           ExchangeRoleResponder,
		ProtocolID:     proto.ProtocolID,
		LocalSessionID: localSessionID,
		Session:        sess,
		PeerAddress:    peerAddr,
		Manager:        m,
	})

	m.mu.Lock()
	m.exchanges[key] = ctx
	m.mu.Unlock()

	// Schedule ACK if reliable
	if proto.Reliability {
		m.scheduleAck(ctx, frame.Header.MessageCounter)
	}

	// Dispatch to protocol handler
	response, err := handler.OnUnsolicited(ctx, proto.ProtocolOpcode, frame.Payload)
	if err != nil {
		// Remove exchange on error
		m.mu.Lock()
		delete(m.exchanges, key)
		m.mu.Unlock()
		return err
	}

	// Send response if any
	if response != nil {
		reliable := peerAddr.TransportType == transport.TransportTypeUDP
		return ctx.SendMessage(proto.ProtocolOpcode, response, reliable)
	}

	return nil
}

// handleReceivedAck processes an incoming ACK.
func (m *Manager) handleReceivedAck(ackedCounter uint32) {
	entry := m.retransmitTable.Ack(ackedCounter)
	if entry != nil {
		// Find the exchange and notify
		m.mu.RLock()
		ctx, exists := m.exchanges[entry.ExchangeKey]
		m.mu.RUnlock()

		if exists {
			ctx.onRetransmitComplete()
		}
	}
}

// scheduleAck schedules an ACK for a received reliable message.
func (m *Manager) scheduleAck(ctx *ExchangeContext, messageCounter uint32) {
	key := ctx.GetKey()

	// Track pending ACK in context
	ctx.SetPendingAck(messageCounter)

	// Add to ACK table with timeout callback
	displaced := m.ackTable.Add(key, messageCounter, func() {
		// Timeout - send standalone ACK
		m.sendStandaloneAck(ctx, messageCounter)
	})

	// If displaced an entry that hadn't sent standalone ACK, send it now
	if displaced != nil {
		m.sendStandaloneAck(ctx, displaced.MessageCounter)
	}
}

// sendStandaloneAck sends a standalone ACK message.
func (m *Manager) sendStandaloneAck(ctx *ExchangeContext, ackedCounter uint32) {
	proto := &message.ProtocolHeader{
		ProtocolID:          message.ProtocolSecureChannel,
		ProtocolOpcode:      uint8(securechannel.OpcodeStandaloneAck),
		ExchangeID:          ctx.ID,
		Initiator:           ctx.Role == ExchangeRoleInitiator,
		Acknowledgement:     true,
		Reliability:         false, // Standalone ACKs are never reliable
		AckedMessageCounter: ackedCounter,
	}

	// Mark standalone ACK sent in table
	key := ctx.GetKey()
	m.ackTable.MarkStandaloneAckSent(key)

	// Clear from context
	ctx.ClearPendingAck()

	// Send (empty payload)
	_ = m.sendMessageInternal(ctx, proto, nil)
}

// sendStandaloneAckForUnsolicited sends ACK for unsolicited message with no exchange.
func (m *Manager) sendStandaloneAckForUnsolicited(
	frame *message.Frame,
	peerAddr transport.PeerAddress,
	sess SessionContext,
) {
	// Create ephemeral context just for ACK
	// Per Spec 4.10.5.2: Create ephemeral exchange, send ACK, close

	var ourRole ExchangeRole
	if frame.Protocol.Initiator {
		ourRole = ExchangeRoleResponder
	} else {
		ourRole = ExchangeRoleInitiator
	}

	proto := &message.ProtocolHeader{
		ProtocolID:          message.ProtocolSecureChannel,
		ProtocolOpcode:      uint8(securechannel.OpcodeStandaloneAck),
		ExchangeID:          frame.Protocol.ExchangeID,
		Initiator:           ourRole == ExchangeRoleInitiator,
		Acknowledgement:     true,
		Reliability:         false,
		AckedMessageCounter: frame.Header.MessageCounter,
	}

	// Encode and send directly
	// This is simplified - full implementation would use session encryption
	_ = proto
	_ = peerAddr
	_ = sess
	// TODO: Implement direct send for ephemeral ACK
}

// flushPendingAck sends any pending ACK for an exchange.
func (m *Manager) flushPendingAck(ctx *ExchangeContext) {
	key := ctx.GetKey()

	if m.ackTable.HasPendingAck(key) {
		counter, _ := m.ackTable.PendingCounter(key)
		m.sendStandaloneAck(ctx, counter)
	}
}

// sendMessage sends a message on an exchange.
func (m *Manager) sendMessage(ctx *ExchangeContext, proto *message.ProtocolHeader, payload []byte) error {
	// Check for pending ACK to piggyback
	if ackCounter, hasAck := ctx.GetPendingAck(); hasAck && !proto.Acknowledgement {
		proto.Acknowledgement = true
		proto.AckedMessageCounter = ackCounter

		// Clear from table (piggybacked, not standalone)
		key := ctx.GetKey()
		m.ackTable.MarkAcked(key)
		ctx.ClearPendingAck()
	}

	return m.sendMessageInternal(ctx, proto, payload)
}

// sendMessageInternal performs the actual send.
func (m *Manager) sendMessageInternal(ctx *ExchangeContext, proto *message.ProtocolHeader, payload []byte) error {
	sess := ctx.Session()
	if sess == nil {
		return ErrSessionNotFound
	}

	// Get secure session for encryption
	secureSession, isSecure := sess.(SecureSessionContext)
	if !isSecure {
		// Unsecured session - encode without encryption
		return m.sendUnsecuredMessage(ctx, sess, proto, payload)
	}

	// Build message header
	header := &message.MessageHeader{
		SessionID: secureSession.PeerSessionID(),
		// MessageCounter will be set by Encrypt
	}

	// Encrypt
	encoded, err := secureSession.Encrypt(header, proto, payload, false)
	if err != nil {
		return err
	}

	// Track for retransmission if reliable
	if proto.Reliability {
		peerAddr := ctx.PeerAddress()
		params := sess.GetParams()

		// Determine base interval (idle vs active)
		baseInterval := params.IdleInterval
		if secureSession.IsPeerActive() {
			baseInterval = params.ActiveInterval
		}

		key := ctx.GetKey()
		err = m.retransmitTable.Add(key, header.MessageCounter, encoded, peerAddr, baseInterval,
			func(entry *RetransmitEntry) {
				m.onRetransmitTimeout(entry)
			})
		if err != nil {
			return err
		}

		ctx.SetPendingRetransmit(header.MessageCounter)
	}

	// Send via transport
	peerAddr := ctx.PeerAddress()
	return m.config.TransportManager.Send(encoded, peerAddr)
}

// onRetransmitTimeout handles retransmission timer expiry.
func (m *Manager) onRetransmitTimeout(entry *RetransmitEntry) {
	// Get session params for backoff
	m.mu.RLock()
	ctx, exists := m.exchanges[entry.ExchangeKey]
	m.mu.RUnlock()

	if !exists {
		// Exchange gone - remove entry
		m.retransmitTable.RemoveByCounter(entry.MessageCounter)
		return
	}

	sess := ctx.Session()
	if sess == nil {
		m.retransmitTable.RemoveByCounter(entry.MessageCounter)
		ctx.onRetransmitComplete()
		return
	}

	params := sess.GetParams()
	baseInterval := params.IdleInterval

	// Check if peer is active (only for secure sessions)
	if secureSession, ok := sess.(SecureSessionContext); ok {
		if secureSession.IsPeerActive() {
			baseInterval = params.ActiveInterval
		}
	}

	// Schedule retransmit
	if !m.retransmitTable.ScheduleRetransmit(entry.MessageCounter, baseInterval) {
		// Max retries exceeded
		ctx.onRetransmitComplete()
		return
	}

	// Retransmit the message
	_ = m.config.TransportManager.Send(entry.Message, entry.PeerAddress)
}

// removeExchange removes an exchange from the manager.
func (m *Manager) removeExchange(ctx *ExchangeContext) {
	key := ctx.GetKey()

	m.mu.Lock()
	delete(m.exchanges, key)
	m.mu.Unlock()

	// Clean up tables
	m.ackTable.Remove(key)
	m.retransmitTable.Remove(key)

	// Notify delegate
	if delegate := ctx.GetDelegate(); delegate != nil {
		delegate.OnClose(ctx)
	}
}

// sendUnsecuredMessage sends a message on an unsecured session.
// Unsecured sessions are used during PASE/CASE handshake before encryption is established.
// Per Spec 4.13.2.1: Session ID = 0 and Session Type = Unicast (0).
func (m *Manager) sendUnsecuredMessage(ctx *ExchangeContext, sess SessionContext, proto *message.ProtocolHeader, payload []byte) error {
	// Get source node ID from unsecured context
	unsecuredCtx, ok := sess.(*session.UnsecuredContext)
	if !ok {
		return ErrSessionNotFound
	}

	// Get next global message counter
	counter, err := m.config.SessionManager.NextGlobalCounter()
	if err != nil {
		return err
	}

	// Build unsecured message header
	// Per Spec 4.4.1: Session ID = 0, Session Type = Unicast for unsecured
	header := &message.MessageHeader{
		SessionID:      0, // Unsecured session
		SessionType:    message.SessionTypeUnicast,
		MessageCounter: counter,
		SourceNodeID:   uint64(unsecuredCtx.EphemeralNodeID()),
		SourcePresent:  true, // Required for unsecured messages
	}

	// Build frame and encode
	frame := &message.Frame{
		Header:   *header,
		Protocol: *proto,
		Payload:  payload,
	}
	encoded := frame.EncodeUnsecured()

	// Track for retransmission if reliable
	if proto.Reliability {
		peerAddr := ctx.PeerAddress()
		params := sess.GetParams()
		baseInterval := params.IdleInterval

		key := ctx.GetKey()
		err = m.retransmitTable.Add(key, counter, encoded, peerAddr, baseInterval,
			func(entry *RetransmitEntry) {
				m.onRetransmitTimeout(entry)
			})
		if err != nil {
			return err
		}

		ctx.SetPendingRetransmit(counter)
	}

	// Send via transport
	peerAddr := ctx.PeerAddress()
	return m.config.TransportManager.Send(encoded, peerAddr)
}

// GetExchange returns an exchange by key, if it exists.
func (m *Manager) GetExchange(localSessionID, exchangeID uint16, role ExchangeRole) (*ExchangeContext, bool) {
	key := exchangeKey{
		localSessionID: localSessionID,
		exchangeID:     exchangeID,
		role:           role,
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	ctx, exists := m.exchanges[key]
	return ctx, exists
}

// ExchangeCount returns the number of active exchanges.
func (m *Manager) ExchangeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.exchanges)
}

// Close shuts down the manager and all exchanges.
func (m *Manager) Close() {
	m.mu.Lock()
	exchanges := make([]*ExchangeContext, 0, len(m.exchanges))
	for _, ctx := range m.exchanges {
		exchanges = append(exchanges, ctx)
	}
	m.mu.Unlock()

	// Close all exchanges
	for _, ctx := range exchanges {
		ctx.Close()
	}

	// Clear tables
	m.ackTable.Clear()
	m.retransmitTable.Clear()
}
