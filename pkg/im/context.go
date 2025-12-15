package im

import (
	"github.com/backkem/matter/pkg/acl"
	"github.com/backkem/matter/pkg/exchange"
	"github.com/backkem/matter/pkg/fabric"
)

// RequestContext provides context for IM operations.
// It wraps the exchange context and provides subject descriptor for ACL checks.
// This is passed to all handler operations and can be used by clusters.
type RequestContext struct {
	// Exchange is the underlying exchange context.
	// Provides access to session info and message sending.
	Exchange *exchange.ExchangeContext

	// Subject describes the identity making the request.
	// Used for ACL validation and fabric-scoped data access.
	Subject acl.SubjectDescriptor
}

// NewRequestContext creates a new request context.
func NewRequestContext(exchCtx *exchange.ExchangeContext, subject acl.SubjectDescriptor) *RequestContext {
	return &RequestContext{
		Exchange: exchCtx,
		Subject:  subject,
	}
}

// FabricIndex returns the accessing fabric index.
func (c *RequestContext) FabricIndex() fabric.FabricIndex {
	return c.Subject.FabricIndex
}

// SourceNodeID returns the requesting node's ID.
func (c *RequestContext) SourceNodeID() uint64 {
	return c.Subject.Subject
}

// IsCommissioning returns true if this is during PASE commissioning.
// During commissioning, implicit Administer privilege is granted.
func (c *RequestContext) IsCommissioning() bool {
	return c.Subject.IsCommissioning
}

// AuthMode returns the authentication mode of the session.
func (c *RequestContext) AuthMode() acl.AuthMode {
	return c.Subject.AuthMode
}
