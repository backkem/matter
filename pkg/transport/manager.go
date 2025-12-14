package transport

import (
	"fmt"
	"net"
	"sync"
)

// Manager coordinates UDP and TCP transports for Matter messaging.
// It provides a unified interface for sending and receiving messages
// over both transport types.
type Manager struct {
	udp     *UDP
	tcp     *TCP
	handler MessageHandler

	mu      sync.RWMutex
	started bool
	closed  bool
}

// ManagerConfig configures the transport manager.
type ManagerConfig struct {
	// Port is the port to listen on (default: 5540).
	Port int

	// UDPEnabled controls whether UDP transport is enabled (default: true).
	UDPEnabled bool

	// TCPEnabled controls whether TCP transport is enabled (default: true).
	TCPEnabled bool

	// MessageHandler is called for each received message.
	// Required.
	MessageHandler MessageHandler

	// UDPConn is an optional pre-existing UDP connection for testing.
	UDPConn net.PacketConn

	// TCPListener is an optional pre-existing TCP listener for testing.
	TCPListener net.Listener
}

// NewManager creates a new transport manager with the given configuration.
func NewManager(config ManagerConfig) (*Manager, error) {
	if config.MessageHandler == nil {
		return nil, ErrNoHandler
	}

	// Apply defaults
	if config.Port == 0 {
		config.Port = DefaultPort
	}

	// Default to both transports enabled if neither is explicitly set
	// (We check if both are false, meaning neither was set)
	if !config.UDPEnabled && !config.TCPEnabled {
		config.UDPEnabled = true
		config.TCPEnabled = true
	}

	m := &Manager{
		handler: config.MessageHandler,
	}

	listenAddr := fmt.Sprintf(":%d", config.Port)

	// Create UDP transport if enabled
	if config.UDPEnabled {
		udp, err := NewUDP(UDPConfig{
			Conn:           config.UDPConn,
			ListenAddr:     listenAddr,
			MessageHandler: config.MessageHandler,
		})
		if err != nil {
			return nil, fmt.Errorf("creating UDP transport: %w", err)
		}
		m.udp = udp
	}

	// Create TCP transport if enabled
	if config.TCPEnabled {
		tcp, err := NewTCP(TCPConfig{
			Listener:       config.TCPListener,
			ListenAddr:     listenAddr,
			MessageHandler: config.MessageHandler,
		})
		if err != nil {
			if m.udp != nil {
				m.udp.Stop()
			}
			return nil, fmt.Errorf("creating TCP transport: %w", err)
		}
		m.tcp = tcp
	}

	return m, nil
}

// Start begins listening for messages on all enabled transports.
func (m *Manager) Start() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	if m.started {
		m.mu.Unlock()
		return ErrAlreadyStarted
	}
	m.started = true
	m.mu.Unlock()

	if m.udp != nil {
		if err := m.udp.Start(); err != nil {
			return fmt.Errorf("starting UDP transport: %w", err)
		}
	}

	if m.tcp != nil {
		if err := m.tcp.Start(); err != nil {
			if m.udp != nil {
				m.udp.Stop()
			}
			return fmt.Errorf("starting TCP transport: %w", err)
		}
	}

	return nil
}

// Stop closes all transports.
func (m *Manager) Stop() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return ErrClosed
	}
	m.closed = true
	m.mu.Unlock()

	var errs []error

	if m.udp != nil {
		if err := m.udp.Stop(); err != nil && err != ErrClosed {
			errs = append(errs, fmt.Errorf("stopping UDP: %w", err))
		}
	}

	if m.tcp != nil {
		if err := m.tcp.Stop(); err != nil && err != ErrClosed {
			errs = append(errs, fmt.Errorf("stopping TCP: %w", err))
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Send sends a message to the specified peer address.
// The transport type is determined by the PeerAddress.TransportType field.
func (m *Manager) Send(data []byte, peer PeerAddress) error {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return ErrClosed
	}
	m.mu.RUnlock()

	if !peer.IsValid() {
		return ErrInvalidAddress
	}

	switch peer.TransportType {
	case TransportTypeUDP:
		if m.udp == nil {
			return fmt.Errorf("UDP transport not enabled")
		}
		return m.udp.Send(data, peer.Addr)
	case TransportTypeTCP:
		if m.tcp == nil {
			return fmt.Errorf("TCP transport not enabled")
		}
		return m.tcp.SendRaw(data, peer.Addr)
	default:
		return ErrInvalidAddress
	}
}

// LocalAddresses returns all local addresses the manager is listening on.
func (m *Manager) LocalAddresses() []net.Addr {
	var addrs []net.Addr

	if m.udp != nil {
		addrs = append(addrs, m.udp.LocalAddr())
	}
	if m.tcp != nil {
		addrs = append(addrs, m.tcp.LocalAddr())
	}

	return addrs
}

// UDP returns the UDP transport, or nil if not enabled.
func (m *Manager) UDP() *UDP {
	return m.udp
}

// TCP returns the TCP transport, or nil if not enabled.
func (m *Manager) TCP() *TCP {
	return m.tcp
}
