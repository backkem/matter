package transport

import (
	"net"
	"sync"
	"time"

	"github.com/backkem/matter/pkg/message"
	"github.com/pion/logging"
)

// DefaultPort is the default Matter port (Spec Section 2.5.6.3).
const DefaultPort = 5540

// UDP provides UDP transport for Matter messages.
// It wraps a net.PacketConn and provides a read loop that calls
// the configured MessageHandler for each received message.
type UDP struct {
	conn    net.PacketConn
	handler MessageHandler
	closeCh chan struct{}
	wg      sync.WaitGroup
	log     logging.LeveledLogger

	mu      sync.RWMutex
	started bool
	closed  bool
}

// UDPConfig configures the UDP transport.
type UDPConfig struct {
	// Conn is an optional pre-existing PacketConn to use.
	// If nil, a new connection will be created using ListenAddr.
	Conn net.PacketConn

	// ListenAddr is the address to listen on (e.g., ":5540").
	// Ignored if Conn is provided.
	ListenAddr string

	// MessageHandler is called for each received message.
	// Required.
	MessageHandler MessageHandler

	// LoggerFactory is the factory for creating loggers.
	// If nil, logging is disabled.
	LoggerFactory logging.LoggerFactory
}

// NewUDP creates a new UDP transport with the given configuration.
func NewUDP(config UDPConfig) (*UDP, error) {
	if config.MessageHandler == nil {
		return nil, ErrNoHandler
	}

	u := &UDP{
		conn:    config.Conn,
		handler: config.MessageHandler,
		closeCh: make(chan struct{}),
	}

	// Create logger
	if config.LoggerFactory != nil {
		u.log = config.LoggerFactory.NewLogger("transport-udp")
	}

	// Create connection if not provided
	if u.conn == nil {
		addr := config.ListenAddr
		if addr == "" {
			addr = ":0" // Use ephemeral port
		}

		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, err
		}
		u.conn = conn
	}

	return u, nil
}

// Start begins the read loop for receiving messages.
// Messages are delivered to the configured MessageHandler.
func (u *UDP) Start() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return ErrClosed
	}
	if u.started {
		u.mu.Unlock()
		return ErrAlreadyStarted
	}
	u.started = true
	u.mu.Unlock()

	if u.log != nil {
		u.log.Infof("starting UDP transport on %s", u.conn.LocalAddr())
	}

	u.wg.Add(1)
	go u.readLoop()

	return nil
}

// Stop closes the transport and waits for the read loop to exit.
func (u *UDP) Stop() error {
	u.mu.Lock()
	if u.closed {
		u.mu.Unlock()
		return ErrClosed
	}
	u.closed = true
	u.mu.Unlock()

	if u.log != nil {
		u.log.Info("stopping UDP transport")
	}

	close(u.closeCh)

	// Set a short deadline to unblock any pending reads
	u.conn.SetReadDeadline(time.Now())
	u.conn.Close()
	u.wg.Wait()

	return nil
}

// Send sends a message to the specified address.
func (u *UDP) Send(data []byte, addr net.Addr) error {
	u.mu.RLock()
	if u.closed {
		u.mu.RUnlock()
		return ErrClosed
	}
	u.mu.RUnlock()

	if addr == nil {
		return ErrInvalidAddress
	}

	if len(data) > message.MaxUDPMessageSize {
		return ErrMessageTooLarge
	}

	if u.log != nil {
		u.log.Debugf("sending %d bytes to %v", len(data), addr)
	}

	_, err := u.conn.WriteTo(data, addr)
	if err != nil {
		if u.log != nil {
			u.log.Warnf("send failed: %v", err)
		}
		return err
	}

	return nil
}

// LocalAddr returns the local address the transport is listening on.
func (u *UDP) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}

// readLoop reads messages from the connection and dispatches them.
func (u *UDP) readLoop() {
	defer u.wg.Done()

	buf := make([]byte, message.MaxUDPMessageSize)

	for {
		select {
		case <-u.closeCh:
			return
		default:
		}

		n, addr, err := u.conn.ReadFrom(buf)
		if err != nil {
			// Check if we're shutting down
			select {
			case <-u.closeCh:
				return
			default:
				if u.log != nil {
					u.log.Warnf("UDP read error: %v", err)
				}
				continue
			}
		}

		if n == 0 {
			continue
		}

		// Make a copy of the data for the handler
		data := make([]byte, n)
		copy(data, buf[:n])

		// Debug logging for received packets
		if u.log != nil {
			u.log.Debugf("received %d bytes from %v", n, addr)
		}

		msg := &ReceivedMessage{
			Data:     data,
			PeerAddr: NewUDPPeerAddress(addr),
		}

		u.handler(msg)
	}
}
