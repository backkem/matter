package commissioning

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/backkem/matter/pkg/exchange"
	"github.com/backkem/matter/pkg/message"
	"github.com/backkem/matter/pkg/securechannel"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/transport"
	"github.com/pion/logging"
)

// PASE protocol errors.
var (
	ErrPASETimeout       = errors.New("pase: handshake timeout")
	ErrPASEProtocol      = errors.New("pase: protocol error")
	ErrPASEUnexpectedMsg = errors.New("pase: unexpected message")
	ErrPASECanceled      = errors.New("pase: handshake canceled")
)

// PASEClient handles PASE session establishment as the initiator.
//
// The PASE flow (initiator perspective):
//  1. Send PBKDFParamRequest
//  2. Receive PBKDFParamResponse
//  3. Send Pake1
//  4. Receive Pake2
//  5. Send Pake3
//  6. Receive StatusReport (success/failure)
//
// This client orchestrates the exchange manager and secure channel manager
// to complete the handshake.
type PASEClient struct {
	exchangeManager *exchange.Manager
	secureChannel   *securechannel.Manager
	sessionManager  *session.Manager
	timeout         time.Duration
	log             logging.LeveledLogger
}

// PASEClientConfig configures the PASEClient.
type PASEClientConfig struct {
	ExchangeManager *exchange.Manager
	SecureChannel   *securechannel.Manager
	SessionManager  *session.Manager
	Timeout         time.Duration

	// LoggerFactory is the factory for creating loggers.
	// If nil, logging is disabled.
	LoggerFactory logging.LoggerFactory
}

// NewPASEClient creates a new PASE client.
func NewPASEClient(config PASEClientConfig) *PASEClient {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = DefaultPASETimeout
	}

	c := &PASEClient{
		exchangeManager: config.ExchangeManager,
		secureChannel:   config.SecureChannel,
		sessionManager:  config.SessionManager,
		timeout:         timeout,
	}

	if config.LoggerFactory != nil {
		c.log = config.LoggerFactory.NewLogger("pase")
	}

	return c
}

// Establish performs the PASE handshake and returns the established secure session.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - peerAddr: Device network address
//   - passcode: Setup passcode from the device
//
// Returns the secure session context on success.
func (c *PASEClient) Establish(
	ctx context.Context,
	peerAddr transport.PeerAddress,
	passcode uint32,
) (*session.SecureContext, error) {
	if c.log != nil {
		c.log.Infof("starting PASE with %s", peerAddr.Addr)
	}

	// Apply timeout
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Create unsecured session context for PASE handshake
	unsecuredSess, err := session.NewUnsecuredContext(session.SessionRoleInitiator)
	if err != nil {
		return nil, err
	}

	// Create PASE handler to process responses
	handler := newPASEHandler(c.secureChannel)

	// Create exchange
	exch, err := c.exchangeManager.NewExchange(
		unsecuredSess,
		0, // Session ID 0 for unsecured
		peerAddr,
		message.ProtocolSecureChannel,
		handler,
	)
	if err != nil {
		return nil, err
	}
	defer exch.Close()

	// Track the exchange ID for the secure channel manager
	exchangeID := exch.ID

	// Step 1: Start PASE - get PBKDFParamRequest
	pbkdfReq, err := c.secureChannel.StartPASE(exchangeID, passcode)
	if err != nil {
		return nil, err
	}

	// Send PBKDFParamRequest
	err = exch.SendMessage(uint8(securechannel.OpcodePBKDFParamRequest), pbkdfReq, true)
	if err != nil {
		return nil, err
	}

	// Step 2: Wait for PBKDFParamResponse and get Pake1
	pake1Msg, err := handler.waitForNextMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("step 2 wait: %w", err)
	}
	if pake1Msg == nil {
		return nil, fmt.Errorf("step 2: pake1Msg is nil")
	}

	// Send Pake1
	err = exch.SendMessage(uint8(pake1Msg.Opcode), pake1Msg.Payload, true)
	if err != nil {
		return nil, fmt.Errorf("step 2 send: %w", err)
	}

	// Step 3: Wait for Pake2 and get Pake3
	pake3Msg, err := handler.waitForNextMessage(ctx)
	if err != nil {
		return nil, fmt.Errorf("step 3 wait: %w", err)
	}
	if pake3Msg == nil {
		return nil, fmt.Errorf("step 3: pake3Msg is nil")
	}

	// Send Pake3
	err = exch.SendMessage(uint8(pake3Msg.Opcode), pake3Msg.Payload, true)
	if err != nil {
		return nil, err
	}

	// Step 4: Wait for StatusReport (session complete)
	_, err = handler.waitForNextMessage(ctx)
	if err != nil {
		return nil, err
	}

	// Find the established PASE session from the session manager.
	// The secure channel manager creates the session when processing StatusReport
	// and notifies via callback, but we need to get the actual session object.
	var secureCtx *session.SecureContext
	c.sessionManager.ForEachSecureSession(func(sess *session.SecureContext) bool {
		if sess.SessionType() == session.SessionTypePASE {
			secureCtx = sess
			return false // Stop iteration
		}
		return true // Continue
	})

	if secureCtx == nil {
		return nil, ErrPASEProtocol
	}

	return secureCtx, nil
}

// paseHandler handles PASE response messages.
type paseHandler struct {
	secureChannel *securechannel.Manager
	exchangeID    uint16

	// Channel for passing processed messages (next message to send or nil on complete)
	msgCh chan paseResult

	// Established session
	session *session.SecureContext

	mu   sync.Mutex
	done bool
}

type paseResult struct {
	nextMsg *securechannel.Message
	err     error
}

func newPASEHandler(secureChannel *securechannel.Manager) *paseHandler {
	return &paseHandler{
		secureChannel: secureChannel,
		msgCh:         make(chan paseResult, 1),
	}
}

// OnMessage implements exchange.ExchangeDelegate.
func (h *paseHandler) OnMessage(
	ctx *exchange.ExchangeContext,
	header *message.ProtocolHeader,
	payload []byte,
) ([]byte, error) {
	h.mu.Lock()
	if h.done {
		h.mu.Unlock()
		return nil, nil
	}
	h.exchangeID = ctx.ID
	h.mu.Unlock()

	opcode := securechannel.Opcode(header.ProtocolOpcode)

	// Skip acknowledgement messages - they're handled by the exchange layer
	// and should not affect the PASE state machine
	if opcode == securechannel.OpcodeStandaloneAck ||
		opcode == securechannel.OpcodeMsgCounterSyncReq ||
		opcode == securechannel.OpcodeMsgCounterSyncResp {
		return nil, nil
	}

	// Route through secure channel manager
	msg := &securechannel.Message{
		Opcode:  opcode,
		Payload: payload,
	}
	nextMsg, err := h.secureChannel.Route(ctx.ID, msg)
	if err != nil {
		h.sendResult(paseResult{err: err})
		return nil, err
	}

	// Check for StatusReport (session complete)
	if opcode == securechannel.OpcodeStatusReport {
		// Parse status to check success
		status, err := securechannel.DecodeStatusReport(payload)
		if err != nil {
			h.sendResult(paseResult{err: err})
			return nil, err
		}

		if !status.IsSuccess() {
			h.sendResult(paseResult{err: ErrPASEProtocol})
			return nil, ErrPASEProtocol
		}

		// Mark done and signal completion with nil next message
		h.mu.Lock()
		h.done = true
		h.mu.Unlock()

		h.sendResult(paseResult{nextMsg: nil})
		return nil, nil
	}

	// Pass the next message to send
	h.sendResult(paseResult{nextMsg: nextMsg})
	return nil, nil
}

// OnClose implements exchange.ExchangeDelegate.
func (h *paseHandler) OnClose(ctx *exchange.ExchangeContext) {
	h.sendResult(paseResult{err: ErrPASECanceled})
}

func (h *paseHandler) sendResult(result paseResult) {
	select {
	case h.msgCh <- result:
	default:
		// Channel full, drop
	}
}

func (h *paseHandler) waitForNextMessage(ctx context.Context) (*securechannel.Message, error) {
	select {
	case <-ctx.Done():
		return nil, ErrPASETimeout
	case result := <-h.msgCh:
		if result.err != nil {
			return nil, result.err
		}
		return result.nextMsg, nil
	}
}

func (h *paseHandler) setSession(sess *session.SecureContext) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.session = sess
}

func (h *paseHandler) getSession() *session.SecureContext {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.session
}
