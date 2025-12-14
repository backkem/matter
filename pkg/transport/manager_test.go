package transport

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestNewManager(t *testing.T) {
	t.Run("with handler", func(t *testing.T) {
		handler := func(msg *ReceivedMessage) {}
		m, err := NewManager(ManagerConfig{
			Port:           0, // Use ephemeral port
			MessageHandler: handler,
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		defer m.Stop()

		if m.udp == nil {
			t.Error("NewManager() UDP is nil")
		}
		if m.tcp == nil {
			t.Error("NewManager() TCP is nil")
		}
	})

	t.Run("without handler", func(t *testing.T) {
		_, err := NewManager(ManagerConfig{
			Port: 0,
		})
		if err != ErrNoHandler {
			t.Errorf("NewManager() error = %v, want %v", err, ErrNoHandler)
		}
	})

	t.Run("UDP only", func(t *testing.T) {
		handler := func(msg *ReceivedMessage) {}
		m, err := NewManager(ManagerConfig{
			Port:           0,
			UDPEnabled:     true,
			TCPEnabled:     false,
			MessageHandler: handler,
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		defer m.Stop()

		if m.udp == nil {
			t.Error("NewManager() UDP is nil")
		}
		if m.tcp != nil {
			t.Error("NewManager() TCP should be nil")
		}
	})

	t.Run("TCP only", func(t *testing.T) {
		handler := func(msg *ReceivedMessage) {}
		m, err := NewManager(ManagerConfig{
			Port:           0,
			UDPEnabled:     false,
			TCPEnabled:     true,
			MessageHandler: handler,
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		defer m.Stop()

		if m.udp != nil {
			t.Error("NewManager() UDP should be nil")
		}
		if m.tcp == nil {
			t.Error("NewManager() TCP is nil")
		}
	})
}

func TestManagerStartStop(t *testing.T) {
	handler := func(msg *ReceivedMessage) {}
	m, err := NewManager(ManagerConfig{
		Port:           0,
		MessageHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}

	// Start
	if err := m.Start(); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	// Double start should fail
	if err := m.Start(); err != ErrAlreadyStarted {
		t.Errorf("Start() second call error = %v, want %v", err, ErrAlreadyStarted)
	}

	// Stop
	if err := m.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	// Double stop should fail
	if err := m.Stop(); err != ErrClosed {
		t.Errorf("Stop() second call error = %v, want %v", err, ErrClosed)
	}
}

func TestManagerSendUDP(t *testing.T) {
	received := make(chan *ReceivedMessage, 1)

	// Create pre-existing connections to avoid port conflicts
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() server error = %v", err)
	}

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() client error = %v", err)
	}

	// Create server manager with injected connection
	server, err := NewManager(ManagerConfig{
		UDPConn:        serverConn,
		UDPEnabled:     true,
		TCPEnabled:     false,
		MessageHandler: func(msg *ReceivedMessage) { received <- msg },
	})
	if err != nil {
		t.Fatalf("NewManager() server error = %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Start() server error = %v", err)
	}
	defer server.Stop()

	// Create client manager with injected connection
	client, err := NewManager(ManagerConfig{
		UDPConn:        clientConn,
		UDPEnabled:     true,
		TCPEnabled:     false,
		MessageHandler: func(msg *ReceivedMessage) {},
	})
	if err != nil {
		t.Fatalf("NewManager() client error = %v", err)
	}
	if err := client.Start(); err != nil {
		t.Fatalf("Start() client error = %v", err)
	}
	defer client.Stop()

	// Send via manager
	testData := []byte("hello via manager UDP")
	peer := NewUDPPeerAddress(server.UDP().LocalAddr())
	if err := client.Send(testData, peer); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case msg := <-received:
		if !bytes.Equal(msg.Data, testData) {
			t.Errorf("received = %s, want %s", msg.Data, testData)
		}
		if msg.PeerAddr.TransportType != TransportTypeUDP {
			t.Errorf("TransportType = %v, want UDP", msg.PeerAddr.TransportType)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for message")
	}
}

func TestManagerSendErrors(t *testing.T) {
	t.Run("invalid peer address", func(t *testing.T) {
		m, err := NewManager(ManagerConfig{
			Port:           0,
			MessageHandler: func(msg *ReceivedMessage) {},
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		defer m.Stop()

		// Invalid transport type
		err = m.Send([]byte{0x01}, PeerAddress{})
		if err != ErrInvalidAddress {
			t.Errorf("Send() error = %v, want %v", err, ErrInvalidAddress)
		}
	})

	t.Run("send after close", func(t *testing.T) {
		m, err := NewManager(ManagerConfig{
			Port:           0,
			MessageHandler: func(msg *ReceivedMessage) {},
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		m.Stop()

		addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:5540")
		err = m.Send([]byte{0x01}, NewUDPPeerAddress(addr))
		if err != ErrClosed {
			t.Errorf("Send() error = %v, want %v", err, ErrClosed)
		}
	})

	t.Run("UDP send when disabled", func(t *testing.T) {
		m, err := NewManager(ManagerConfig{
			Port:           0,
			UDPEnabled:     false,
			TCPEnabled:     true,
			MessageHandler: func(msg *ReceivedMessage) {},
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		defer m.Stop()

		addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:5540")
		err = m.Send([]byte{0x01}, NewUDPPeerAddress(addr))
		if err == nil {
			t.Error("Send() expected error for disabled UDP")
		}
	})

	t.Run("TCP send when disabled", func(t *testing.T) {
		m, err := NewManager(ManagerConfig{
			Port:           0,
			UDPEnabled:     true,
			TCPEnabled:     false,
			MessageHandler: func(msg *ReceivedMessage) {},
		})
		if err != nil {
			t.Fatalf("NewManager() error = %v", err)
		}
		defer m.Stop()

		addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:5540")
		err = m.Send([]byte{0x01}, NewTCPPeerAddress(addr))
		if err == nil {
			t.Error("Send() expected error for disabled TCP")
		}
	})
}

func TestManagerLocalAddresses(t *testing.T) {
	m, err := NewManager(ManagerConfig{
		Port:           0,
		MessageHandler: func(msg *ReceivedMessage) {},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Stop()

	addrs := m.LocalAddresses()
	if len(addrs) != 2 {
		t.Errorf("LocalAddresses() count = %d, want 2", len(addrs))
	}

	// Verify we have both UDP and TCP addresses
	hasUDP, hasTCP := false, false
	for _, addr := range addrs {
		switch addr.(type) {
		case *net.UDPAddr:
			hasUDP = true
		case *net.TCPAddr:
			hasTCP = true
		}
	}

	if !hasUDP {
		t.Error("LocalAddresses() missing UDP address")
	}
	if !hasTCP {
		t.Error("LocalAddresses() missing TCP address")
	}
}

func TestManagerAccessors(t *testing.T) {
	m, err := NewManager(ManagerConfig{
		Port:           0,
		MessageHandler: func(msg *ReceivedMessage) {},
	})
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer m.Stop()

	if m.UDP() == nil {
		t.Error("UDP() = nil")
	}
	if m.TCP() == nil {
		t.Error("TCP() = nil")
	}
}
