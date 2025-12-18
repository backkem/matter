package im

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/backkem/matter/pkg/exchange"
	imsg "github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/message"
	"github.com/backkem/matter/pkg/session"
	"github.com/backkem/matter/pkg/tlv"
	"github.com/backkem/matter/pkg/transport"
	"github.com/pion/logging"
)

// Client errors.
var (
	ErrClientTimeout      = errors.New("im: request timeout")
	ErrClientClosed       = errors.New("im: client closed")
	ErrUnexpectedResponse = errors.New("im: unexpected response type")
	ErrCommandFailed      = errors.New("im: command failed")
)

// DefaultRequestTimeout is the default timeout for IM requests.
const DefaultRequestTimeout = 30 * time.Second

// Client provides client-side IM operations for sending cluster commands.
// It wraps the exchange layer to provide a synchronous request-response API.
//
// Usage:
//
//	client := im.NewClient(exchangeManager)
//	resp, err := client.Invoke(ctx, session, path, request)
type Client struct {
	exchangeManager *exchange.Manager
	timeout         time.Duration
	log             logging.LeveledLogger
}

// ClientConfig configures the Client.
type ClientConfig struct {
	// ExchangeManager handles message exchanges.
	// Required.
	ExchangeManager *exchange.Manager

	// Timeout for requests. Defaults to DefaultRequestTimeout if zero.
	Timeout time.Duration

	// LoggerFactory creates loggers for the client.
	// If nil, logging is disabled.
	LoggerFactory logging.LoggerFactory
}

// NewClient creates a new IM client.
func NewClient(config ClientConfig) *Client {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = DefaultRequestTimeout
	}

	c := &Client{
		exchangeManager: config.ExchangeManager,
		timeout:         timeout,
	}

	if config.LoggerFactory != nil {
		c.log = config.LoggerFactory.NewLogger("im-client")
	}

	return c
}

// InvokeRequest sends a command to a cluster and waits for the response.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - sess: Secure session to use for the request
//   - peerAddr: Peer network address
//   - endpointID: Target endpoint (typically 0 for root)
//   - clusterID: Target cluster ID
//   - commandID: Command ID to invoke
//   - requestData: TLV-encoded request fields (can be nil for commands with no fields)
//
// Returns the TLV-encoded response data and error.
func (c *Client) InvokeRequest(
	ctx context.Context,
	sess *session.SecureContext,
	peerAddr transport.PeerAddress,
	endpointID uint16,
	clusterID uint32,
	commandID uint32,
	requestData []byte,
) ([]byte, error) {
	// Apply timeout
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Build InvokeRequestMessage
	req := &imsg.InvokeRequestMessage{
		SuppressResponse: false,
		TimedRequest:     false,
		InvokeRequests: []imsg.CommandDataIB{
			{
				Path: imsg.CommandPathIB{
					Endpoint: imsg.EndpointID(endpointID),
					Cluster:  imsg.ClusterID(clusterID),
					Command:  imsg.CommandID(commandID),
				},
				Fields: requestData,
			},
		},
	}

	// Encode to TLV
	payload, err := EncodeInvokeRequest(req)
	if err != nil {
		return nil, err
	}

	if c.log != nil {
		c.log.Debugf("InvokeRequest: endpoint=%d, cluster=0x%04x, command=0x%02x",
			endpointID, clusterID, commandID)
	}

	// Create response handler
	handler := newInvokeResponseHandler(c.log)

	// Create exchange
	exch, err := c.exchangeManager.NewExchange(
		sess,
		sess.LocalSessionID(),
		peerAddr,
		ProtocolID,
		handler,
	)
	if err != nil {
		return nil, err
	}
	defer exch.Close()

	// Send request
	err = exch.SendMessage(uint8(imsg.OpcodeInvokeRequest), payload, true)
	if err != nil {
		return nil, err
	}

	// Wait for response
	select {
	case <-ctx.Done():
		if c.log != nil {
			c.log.Warnf("InvokeRequest timeout: endpoint=%d, cluster=0x%04x, command=0x%02x",
				endpointID, clusterID, commandID)
		}
		return nil, ErrClientTimeout
	case result := <-handler.resultCh:
		if result.err != nil {
			if c.log != nil {
				c.log.Warnf("InvokeRequest error: %v", result.err)
			}
			return nil, result.err
		}
		return result.data, nil
	}
}

// InvokeResult is the result of an invoke operation.
type InvokeResult struct {
	// ResponseData is the TLV-encoded response fields.
	ResponseData []byte

	// Status is the IM status if command returned status instead of data.
	Status imsg.Status

	// ClusterStatus is the cluster-specific status code if present.
	ClusterStatus *uint16

	// HasStatus indicates whether this is a status response vs data response.
	HasStatus bool
}

// InvokeWithStatus sends a command and returns the full result including status.
func (c *Client) InvokeWithStatus(
	ctx context.Context,
	sess *session.SecureContext,
	peerAddr transport.PeerAddress,
	endpointID uint16,
	clusterID uint32,
	commandID uint32,
	requestData []byte,
) (*InvokeResult, error) {
	// Apply timeout
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Build InvokeRequestMessage
	req := &imsg.InvokeRequestMessage{
		SuppressResponse: false,
		TimedRequest:     false,
		InvokeRequests: []imsg.CommandDataIB{
			{
				Path: imsg.CommandPathIB{
					Endpoint: imsg.EndpointID(endpointID),
					Cluster:  imsg.ClusterID(clusterID),
					Command:  imsg.CommandID(commandID),
				},
				Fields: requestData,
			},
		},
	}

	// Encode to TLV
	payload, err := EncodeInvokeRequest(req)
	if err != nil {
		return nil, err
	}

	if c.log != nil {
		c.log.Debugf("InvokeWithStatus: endpoint=%d, cluster=0x%04x, command=0x%02x",
			endpointID, clusterID, commandID)
	}

	// Create response handler
	handler := newInvokeResponseHandler(c.log)

	// Create exchange
	exch, err := c.exchangeManager.NewExchange(
		sess,
		sess.LocalSessionID(),
		peerAddr,
		ProtocolID,
		handler,
	)
	if err != nil {
		return nil, err
	}
	defer exch.Close()

	// Send request
	err = exch.SendMessage(uint8(imsg.OpcodeInvokeRequest), payload, true)
	if err != nil {
		return nil, err
	}

	// Wait for response
	select {
	case <-ctx.Done():
		if c.log != nil {
			c.log.Warnf("InvokeWithStatus timeout: endpoint=%d, cluster=0x%04x, command=0x%02x",
				endpointID, clusterID, commandID)
		}
		return nil, ErrClientTimeout
	case result := <-handler.resultCh:
		if result.err != nil {
			if c.log != nil {
				c.log.Warnf("InvokeWithStatus error: %v", result.err)
			}
			return nil, result.err
		}
		return result.invokeResult, nil
	}
}

// ReadAttribute reads a single attribute from a cluster.
func (c *Client) ReadAttribute(
	ctx context.Context,
	sess *session.SecureContext,
	peerAddr transport.PeerAddress,
	endpointID uint16,
	clusterID uint32,
	attributeID uint32,
) ([]byte, error) {
	// Apply timeout
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	// Build ReadRequestMessage
	epID := imsg.EndpointID(endpointID)
	clID := imsg.ClusterID(clusterID)
	atID := imsg.AttributeID(attributeID)

	req := &imsg.ReadRequestMessage{
		AttributeRequests: []imsg.AttributePathIB{
			{
				Endpoint:  &epID,
				Cluster:   &clID,
				Attribute: &atID,
			},
		},
		FabricFiltered: true,
	}

	// Encode to TLV
	payload, err := EncodeReadRequest(req)
	if err != nil {
		return nil, err
	}

	if c.log != nil {
		c.log.Debugf("ReadAttribute: endpoint=%d, cluster=0x%04x, attribute=0x%04x",
			endpointID, clusterID, attributeID)
	}

	// Create response handler
	handler := newReadResponseHandler(c.log)

	// Create exchange
	exch, err := c.exchangeManager.NewExchange(
		sess,
		sess.LocalSessionID(),
		peerAddr,
		ProtocolID,
		handler,
	)
	if err != nil {
		return nil, err
	}
	defer exch.Close()

	// Send request
	err = exch.SendMessage(uint8(imsg.OpcodeReadRequest), payload, true)
	if err != nil {
		return nil, err
	}

	// Wait for response
	select {
	case <-ctx.Done():
		if c.log != nil {
			c.log.Warnf("ReadAttribute timeout: endpoint=%d, cluster=0x%04x, attribute=0x%04x",
				endpointID, clusterID, attributeID)
		}
		return nil, ErrClientTimeout
	case result := <-handler.resultCh:
		if result.err != nil {
			if c.log != nil {
				c.log.Warnf("ReadAttribute error: %v", result.err)
			}
			return nil, result.err
		}
		return result.data, nil
	}
}

// responseResult holds the result of a response.
type responseResult struct {
	data         []byte
	invokeResult *InvokeResult
	err          error
}

// invokeResponseHandler handles InvokeResponse messages.
type invokeResponseHandler struct {
	resultCh chan responseResult
	once     sync.Once
	log      logging.LeveledLogger
}

func newInvokeResponseHandler(log logging.LeveledLogger) *invokeResponseHandler {
	return &invokeResponseHandler{
		resultCh: make(chan responseResult, 1),
		log:      log,
	}
}

// OnMessage implements exchange.ExchangeDelegate.
func (h *invokeResponseHandler) OnMessage(
	ctx *exchange.ExchangeContext,
	header *message.ProtocolHeader,
	payload []byte,
) ([]byte, error) {
	opcode := imsg.Opcode(header.ProtocolOpcode)

	if h.log != nil {
		h.log.Tracef("invokeResponseHandler received opcode=%d (%s), exchangeID=%d, payloadLen=%d",
			opcode, opcode.String(), header.ExchangeID, len(payload))
	}

	switch opcode {
	case imsg.OpcodeInvokeResponse:
		h.handleInvokeResponse(payload)
	case imsg.OpcodeStatusResponse:
		h.handleStatusResponse(payload)
	default:
		if h.log != nil {
			h.log.Warnf("invokeResponseHandler unexpected opcode=%d (%s), expected InvokeResponse or StatusResponse",
				opcode, opcode.String())
		}
		h.sendError(ErrUnexpectedResponse)
	}

	return nil, nil
}

// OnClose implements exchange.ExchangeDelegate.
func (h *invokeResponseHandler) OnClose(ctx *exchange.ExchangeContext) {
	h.sendError(ErrClientClosed)
}

func (h *invokeResponseHandler) handleInvokeResponse(payload []byte) {
	resp, err := DecodeInvokeResponse(payload)
	if err != nil {
		h.sendError(err)
		return
	}

	// Extract first response
	if len(resp.InvokeResponses) == 0 {
		h.sendError(ErrUnexpectedResponse)
		return
	}

	first := resp.InvokeResponses[0]

	result := &InvokeResult{}

	// Check if it's a command response or status
	if first.Command != nil {
		result.ResponseData = first.Command.Fields
		result.HasStatus = false
	} else if first.Status != nil {
		result.Status = first.Status.Status.Status
		// Convert *uint8 to *uint16 if present
		if first.Status.Status.ClusterStatus != nil {
			cs := uint16(*first.Status.Status.ClusterStatus)
			result.ClusterStatus = &cs
		}
		result.HasStatus = true
	}

	h.once.Do(func() {
		h.resultCh <- responseResult{
			data:         result.ResponseData,
			invokeResult: result,
		}
	})
}

func (h *invokeResponseHandler) handleStatusResponse(payload []byte) {
	statusMsg, err := DecodeStatusResponse(payload)
	if err != nil {
		h.sendError(err)
		return
	}

	// Status response typically indicates an error
	h.once.Do(func() {
		h.resultCh <- responseResult{
			invokeResult: &InvokeResult{
				Status:    statusMsg.Status,
				HasStatus: true,
			},
		}
	})
}

func (h *invokeResponseHandler) sendError(err error) {
	h.once.Do(func() {
		h.resultCh <- responseResult{err: err}
	})
}

// readResponseHandler handles ReportData messages.
type readResponseHandler struct {
	resultCh chan responseResult
	once     sync.Once
	log      logging.LeveledLogger
}

func newReadResponseHandler(log logging.LeveledLogger) *readResponseHandler {
	return &readResponseHandler{
		resultCh: make(chan responseResult, 1),
		log:      log,
	}
}

// OnMessage implements exchange.ExchangeDelegate.
func (h *readResponseHandler) OnMessage(
	ctx *exchange.ExchangeContext,
	header *message.ProtocolHeader,
	payload []byte,
) ([]byte, error) {
	opcode := imsg.Opcode(header.ProtocolOpcode)

	if h.log != nil {
		h.log.Tracef("readResponseHandler received opcode=%d (%s), exchangeID=%d, payloadLen=%d",
			opcode, opcode.String(), header.ExchangeID, len(payload))
	}

	switch opcode {
	case imsg.OpcodeReportData:
		h.handleReportData(payload)
	case imsg.OpcodeStatusResponse:
		h.handleStatusResponse(payload)
	default:
		if h.log != nil {
			h.log.Warnf("readResponseHandler unexpected opcode=%d (%s), expected ReportData or StatusResponse",
				opcode, opcode.String())
		}
		h.sendError(ErrUnexpectedResponse)
	}

	return nil, nil
}

// OnClose implements exchange.ExchangeDelegate.
func (h *readResponseHandler) OnClose(ctx *exchange.ExchangeContext) {
	h.sendError(ErrClientClosed)
}

func (h *readResponseHandler) handleReportData(payload []byte) {
	resp, err := DecodeReportData(payload)
	if err != nil {
		h.sendError(err)
		return
	}

	// Extract first attribute report
	if len(resp.AttributeReports) == 0 {
		h.sendError(ErrUnexpectedResponse)
		return
	}

	first := resp.AttributeReports[0]

	// Check if it's data or status
	if first.AttributeData != nil {
		h.once.Do(func() {
			h.resultCh <- responseResult{data: first.AttributeData.Data}
		})
	} else if first.AttributeStatus != nil {
		// Attribute access failed - Status is a value, not pointer
		h.sendError(errors.New("im: attribute read failed: " + first.AttributeStatus.Status.Status.String()))
	} else {
		h.sendError(ErrUnexpectedResponse)
	}
}

func (h *readResponseHandler) handleStatusResponse(payload []byte) {
	statusMsg, err := DecodeStatusResponse(payload)
	if err != nil {
		h.sendError(err)
		return
	}

	h.sendError(errors.New("im: read failed with status: " + statusMsg.Status.String()))
}

func (h *readResponseHandler) sendError(err error) {
	h.once.Do(func() {
		h.resultCh <- responseResult{err: err}
	})
}

// EncodeInvokeRequest encodes an InvokeRequestMessage to TLV.
func EncodeInvokeRequest(req *imsg.InvokeRequestMessage) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := req.Encode(w); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// EncodeReadRequest encodes a ReadRequestMessage to TLV.
func EncodeReadRequest(req *imsg.ReadRequestMessage) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)

	if err := req.Encode(w); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DecodeInvokeResponse decodes an InvokeResponseMessage from TLV.
func DecodeInvokeResponse(data []byte) (*imsg.InvokeResponseMessage, error) {
	r := tlv.NewReader(bytes.NewReader(data))

	msg := &imsg.InvokeResponseMessage{}
	if err := msg.Decode(r); err != nil {
		return nil, err
	}

	return msg, nil
}

// DecodeReportData decodes a ReportDataMessage from TLV.
func DecodeReportData(data []byte) (*imsg.ReportDataMessage, error) {
	r := tlv.NewReader(bytes.NewReader(data))

	msg := &imsg.ReportDataMessage{}
	if err := msg.Decode(r); err != nil {
		return nil, err
	}

	return msg, nil
}
