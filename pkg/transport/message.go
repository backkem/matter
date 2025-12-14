package transport

// ReceivedMessage represents an incoming message from the network.
// The Data field contains the raw message bytes as received from the wire,
// including the Matter message header, payload, and MIC (if encrypted).
// Higher layers are responsible for parsing and processing the message.
type ReceivedMessage struct {
	// Data contains the raw message bytes.
	Data []byte
	// PeerAddr identifies the source of the message.
	PeerAddr PeerAddress
}

// MessageHandler is called for each received message.
// Implementations should process messages quickly or dispatch to a goroutine
// to avoid blocking the transport's read loop.
type MessageHandler func(msg *ReceivedMessage)
