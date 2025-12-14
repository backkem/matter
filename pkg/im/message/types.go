package message

// Type aliases for Matter data types used in Interaction Model messages.
// These provide type safety and clarity when working with IDs.

type (
	// NodeID is a 64-bit node identifier.
	NodeID uint64

	// EndpointID is a 16-bit endpoint identifier.
	EndpointID uint16

	// ClusterID is a 32-bit cluster identifier.
	ClusterID uint32

	// AttributeID is a 32-bit attribute identifier.
	AttributeID uint32

	// CommandID is a 32-bit command identifier.
	CommandID uint32

	// EventID is a 32-bit event identifier.
	EventID uint32

	// ListIndex is a 16-bit list index for addressing list elements.
	ListIndex uint16

	// DataVersion is a 32-bit version number for attribute data.
	DataVersion uint32

	// EventNumber is a 64-bit monotonically increasing event counter.
	EventNumber uint64

	// SubscriptionID is a 32-bit subscription identifier.
	SubscriptionID uint32
)

// Helper functions for creating pointers to values.
// Useful for setting optional fields in IBs.

func Ptr[T any](v T) *T {
	return &v
}
