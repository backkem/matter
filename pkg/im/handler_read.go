package im

import (
	"bytes"
	"errors"
	"sync"

	"github.com/backkem/matter/pkg/exchange"
	"github.com/backkem/matter/pkg/im/message"
	"github.com/backkem/matter/pkg/tlv"
)

// ReadHandler errors.
var (
	ErrReadHandlerBusy     = errors.New("read handler: busy processing another request")
	ErrReadPathNotFound    = errors.New("read handler: path not found")
	ErrReadAccessDenied    = errors.New("read handler: access denied")
)

// AttributeReader is called to read attribute data.
// It receives the attribute path and returns the TLV-encoded data.
type AttributeReader func(
	ctx *ReadContext,
	path message.AttributePathIB,
) (*AttributeResult, error)

// AttributeResult is the result of reading an attribute.
type AttributeResult struct {
	// DataVersion is the current data version of the cluster.
	DataVersion message.DataVersion

	// Data is the TLV-encoded attribute value.
	Data []byte

	// Status is set if the read failed with a status.
	Status *message.StatusIB
}

// ReadContext provides context for attribute reads.
type ReadContext struct {
	// Exchange is the underlying exchange context.
	Exchange *exchange.ExchangeContext

	// FabricIndex is the accessing fabric (0 if none).
	FabricIndex uint8

	// IsFabricFiltered indicates fabric-filtered read.
	IsFabricFiltered bool

	// SourceNodeID is the requesting node.
	SourceNodeID uint64
}

// ReadHandlerState represents the handler state machine.
type ReadHandlerState int

const (
	ReadHandlerStateIdle ReadHandlerState = iota
	ReadHandlerStateProcessing
	ReadHandlerStateSendingReport
)

// String returns the state name.
func (s ReadHandlerState) String() string {
	switch s {
	case ReadHandlerStateIdle:
		return "Idle"
	case ReadHandlerStateProcessing:
		return "Processing"
	case ReadHandlerStateSendingReport:
		return "SendingReport"
	default:
		return "Unknown"
	}
}

// ReadHandler handles read request messages.
// This is a simplified implementation for Descriptor/Basic clusters.
// It does NOT support:
//   - Wildcard path expansion (concrete paths only)
//   - Complex ACL checks (assumes caller validated access)
//   - Chunked report assembly (single response)
//
// For full IM spec compliance, see docs/pkgs/im-plan.md.
type ReadHandler struct {
	// attributeReader is called to read attributes.
	attributeReader AttributeReader

	// fragmenter for chunked responses
	fragmenter *Fragmenter

	// State
	state ReadHandlerState
	ctx   *ReadContext

	// Pending response chunks
	pendingChunks []*message.ReportDataMessage
	chunkIndex    int

	mu sync.Mutex
}

// NewReadHandler creates a new read handler.
func NewReadHandler(reader AttributeReader, maxPayload int) *ReadHandler {
	return &ReadHandler{
		attributeReader: reader,
		fragmenter:      NewFragmenter(maxPayload),
		state:           ReadHandlerStateIdle,
	}
}

// HandleReadRequest processes an incoming ReadRequestMessage.
// Returns the ReportData response message.
func (h *ReadHandler) HandleReadRequest(
	exchCtx *exchange.ExchangeContext,
	msg *message.ReadRequestMessage,
	fabricIndex uint8,
	sourceNodeID uint64,
) (*message.ReportDataMessage, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Create read context
	h.ctx = &ReadContext{
		Exchange:         exchCtx,
		FabricIndex:      fabricIndex,
		IsFabricFiltered: msg.FabricFiltered,
		SourceNodeID:     sourceNodeID,
	}

	h.state = ReadHandlerStateProcessing

	// Process attribute requests
	var attributeReports []message.AttributeReportIB

	for _, attrPath := range msg.AttributeRequests {
		report := h.readAttribute(&attrPath, msg.DataVersionFilters)
		attributeReports = append(attributeReports, report)
	}

	// Note: EventRequests are not handled in this simple implementation.
	// For WebRTC, events are pushed via unsolicited reports, not pulled.

	// Build response
	response := &message.ReportDataMessage{
		AttributeReports:    attributeReports,
		SuppressResponse:    true, // Read responses suppress further response
		MoreChunkedMessages: false,
	}

	// Check if response needs chunking
	chunks, err := h.fragmenter.FragmentReportData(response)
	if err != nil {
		h.state = ReadHandlerStateIdle
		return nil, err
	}

	if len(chunks) == 1 {
		h.state = ReadHandlerStateIdle
		return chunks[0], nil
	}

	// Chunked response
	h.state = ReadHandlerStateSendingReport
	h.pendingChunks = chunks
	h.chunkIndex = 1

	return chunks[0], nil
}

// HandleStatusResponse processes a StatusResponse during chunked transmission.
func (h *ReadHandler) HandleStatusResponse(status message.Status) (*message.ReportDataMessage, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.state != ReadHandlerStateSendingReport {
		return nil, nil
	}

	if status != message.StatusSuccess {
		h.state = ReadHandlerStateIdle
		h.pendingChunks = nil
		return nil, nil
	}

	if h.chunkIndex >= len(h.pendingChunks) {
		h.state = ReadHandlerStateIdle
		h.pendingChunks = nil
		return nil, nil
	}

	chunk := h.pendingChunks[h.chunkIndex]
	h.chunkIndex++

	if h.chunkIndex >= len(h.pendingChunks) {
		h.state = ReadHandlerStateIdle
		h.pendingChunks = nil
	}

	return chunk, nil
}

// readAttribute reads a single attribute and returns a report IB.
func (h *ReadHandler) readAttribute(
	path *message.AttributePathIB,
	dataVersionFilters []message.DataVersionFilterIB,
) message.AttributeReportIB {
	if h.attributeReader == nil {
		return h.createAttributeStatusReport(path, message.StatusUnsupportedAttribute)
	}

	// Check data version filter
	if h.shouldSkipForDataVersion(path, dataVersionFilters) {
		// Skip - attribute unchanged. Return empty (will be filtered).
		// Per spec, if version matches, we don't report.
		// But for simplicity, we return a status indicating no change.
		// In practice, we'd just not include this in the response.
		return message.AttributeReportIB{}
	}

	result, err := h.attributeReader(h.ctx, *path)
	if err != nil {
		return h.createAttributeStatusReport(path, message.StatusFailure)
	}

	if result == nil {
		return h.createAttributeStatusReport(path, message.StatusUnsupportedAttribute)
	}

	if result.Status != nil {
		return message.AttributeReportIB{
			AttributeStatus: &message.AttributeStatusIB{
				Path:   *path,
				Status: *result.Status,
			},
		}
	}

	return message.AttributeReportIB{
		AttributeData: &message.AttributeDataIB{
			DataVersion: result.DataVersion,
			Path:        *path,
			Data:        result.Data,
		},
	}
}

// shouldSkipForDataVersion checks if the attribute should be skipped due to version filter.
func (h *ReadHandler) shouldSkipForDataVersion(
	path *message.AttributePathIB,
	filters []message.DataVersionFilterIB,
) bool {
	if len(filters) == 0 {
		return false
	}

	// Find matching filter
	for _, filter := range filters {
		if h.pathMatchesFilter(path, &filter.Path) {
			// For now, we don't track data versions, so always report.
			// A full implementation would compare filter.DataVersion with current version.
			return false
		}
	}

	return false
}

// pathMatchesFilter checks if an attribute path matches a cluster path filter.
func (h *ReadHandler) pathMatchesFilter(attrPath *message.AttributePathIB, filterPath *message.ClusterPathIB) bool {
	if filterPath.Endpoint != nil && attrPath.Endpoint != nil {
		if *filterPath.Endpoint != *attrPath.Endpoint {
			return false
		}
	}
	if filterPath.Cluster != nil && attrPath.Cluster != nil {
		if *filterPath.Cluster != *attrPath.Cluster {
			return false
		}
	}
	return true
}

// createAttributeStatusReport creates an error status report.
func (h *ReadHandler) createAttributeStatusReport(path *message.AttributePathIB, status message.Status) message.AttributeReportIB {
	return message.AttributeReportIB{
		AttributeStatus: &message.AttributeStatusIB{
			Path: *path,
			Status: message.StatusIB{
				Status: status,
			},
		},
	}
}

// Reset resets the handler to idle state.
func (h *ReadHandler) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.state = ReadHandlerStateIdle
	h.ctx = nil
	h.pendingChunks = nil
	h.chunkIndex = 0
}

// State returns the current handler state.
func (h *ReadHandler) State() ReadHandlerState {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// EncodeReportData encodes a report data message.
func EncodeReportData(msg *message.ReportDataMessage) ([]byte, error) {
	var buf bytes.Buffer
	w := tlv.NewWriter(&buf)
	if err := msg.Encode(w); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeReadRequest decodes a read request message.
func DecodeReadRequest(data []byte) (*message.ReadRequestMessage, error) {
	r := tlv.NewReader(bytes.NewReader(data))
	var msg message.ReadRequestMessage
	if err := msg.Decode(r); err != nil {
		return nil, err
	}
	return &msg, nil
}
