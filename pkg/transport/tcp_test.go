package transport

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestNewTCP(t *testing.T) {
	t.Run("with handler", func(t *testing.T) {
		handler := func(msg *ReceivedMessage) {}
		tcp, err := NewTCP(TCPConfig{
			ListenAddr:     "127.0.0.1:0",
			MessageHandler: handler,
		})
		if err != nil {
			t.Fatalf("NewTCP() error = %v", err)
		}
		defer tcp.Stop()

		if tcp.listener == nil {
			t.Error("NewTCP() listener is nil")
		}
	})

	t.Run("without handler", func(t *testing.T) {
		_, err := NewTCP(TCPConfig{
			ListenAddr: "127.0.0.1:0",
		})
		if err != ErrNoHandler {
			t.Errorf("NewTCP() error = %v, want %v", err, ErrNoHandler)
		}
	})

	t.Run("with injected listener", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen() error = %v", err)
		}

		handler := func(msg *ReceivedMessage) {}
		tcp, err := NewTCP(TCPConfig{
			Listener:       listener,
			MessageHandler: handler,
		})
		if err != nil {
			t.Fatalf("NewTCP() error = %v", err)
		}
		defer tcp.Stop()

		if tcp.listener != listener {
			t.Error("NewTCP() did not use injected listener")
		}
	})
}

func TestTCPStartStop(t *testing.T) {
	handler := func(msg *ReceivedMessage) {}
	tcp, err := NewTCP(TCPConfig{
		ListenAddr:     "127.0.0.1:0",
		MessageHandler: handler,
	})
	if err != nil {
		t.Fatalf("NewTCP() error = %v", err)
	}

	// Start
	if err := tcp.Start(); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	// Double start should fail
	if err := tcp.Start(); err != ErrAlreadyStarted {
		t.Errorf("Start() second call error = %v, want %v", err, ErrAlreadyStarted)
	}

	// Stop
	if err := tcp.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	// Double stop should fail
	if err := tcp.Stop(); err != ErrClosed {
		t.Errorf("Stop() second call error = %v, want %v", err, ErrClosed)
	}
}

func TestTCPWithPipe(t *testing.T) {
	// Test using net.Pipe for deterministic in-memory testing
	received := make(chan *ReceivedMessage, 1)

	tcp, err := NewTCP(TCPConfig{
		ListenAddr:     "127.0.0.1:0",
		MessageHandler: func(msg *ReceivedMessage) { received <- msg },
	})
	if err != nil {
		t.Fatalf("NewTCP() error = %v", err)
	}
	if err := tcp.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer tcp.Stop()

	// Create a pipe connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	// Add the server side of the pipe to the TCP transport
	tcp.AddConnection(serverConn)

	// Send a length-prefixed message from client side
	testData := []byte{0x00, 0x01, 0x02, 0x03, 0x04}
	// Write 4-byte length prefix (little-endian)
	lenBuf := []byte{byte(len(testData)), 0, 0, 0}
	if _, err := clientConn.Write(lenBuf); err != nil {
		t.Fatalf("Write length error = %v", err)
	}
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatalf("Write data error = %v", err)
	}

	select {
	case msg := <-received:
		if !bytes.Equal(msg.Data, testData) {
			t.Errorf("received data = %v, want %v", msg.Data, testData)
		}
		if msg.PeerAddr.TransportType != TransportTypeTCP {
			t.Errorf("TransportType = %v, want TCP", msg.PeerAddr.TransportType)
		}
	case <-time.After(time.Second):
		t.Error("timeout waiting for message")
	}
}

func TestTCPRoundtrip(t *testing.T) {
	received1 := make(chan *ReceivedMessage, 1)
	received2 := make(chan *ReceivedMessage, 1)

	// Create server
	server, err := NewTCP(TCPConfig{
		ListenAddr:     "127.0.0.1:0",
		MessageHandler: func(msg *ReceivedMessage) { received1 <- msg },
	})
	if err != nil {
		t.Fatalf("NewTCP() server error = %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Start() server error = %v", err)
	}
	defer server.Stop()

	// Create client
	client, err := NewTCP(TCPConfig{
		ListenAddr:     "127.0.0.1:0",
		MessageHandler: func(msg *ReceivedMessage) { received2 <- msg },
	})
	if err != nil {
		t.Fatalf("NewTCP() client error = %v", err)
	}
	if err := client.Start(); err != nil {
		t.Fatalf("Start() client error = %v", err)
	}
	defer client.Stop()

	// Client sends to server
	testData := []byte("hello from client")
	if err := client.SendRaw(testData, server.LocalAddr()); err != nil {
		t.Fatalf("SendRaw() error = %v", err)
	}

	select {
	case msg := <-received1:
		if !bytes.Equal(msg.Data, testData) {
			t.Errorf("server received = %s, want %s", msg.Data, testData)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for message at server")
	}
}

func TestTCPLocalAddr(t *testing.T) {
	tcp, err := NewTCP(TCPConfig{
		ListenAddr:     "127.0.0.1:0",
		MessageHandler: func(msg *ReceivedMessage) {},
	})
	if err != nil {
		t.Fatalf("NewTCP() error = %v", err)
	}
	defer tcp.Stop()

	addr := tcp.LocalAddr()
	if addr == nil {
		t.Error("LocalAddr() = nil")
	}

	// Verify it's a TCP address
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		t.Errorf("LocalAddr() type = %T, want *net.TCPAddr", addr)
	}

	if tcpAddr.Port == 0 {
		t.Error("LocalAddr() port = 0, want ephemeral port")
	}
}

func TestTCPSendErrors(t *testing.T) {
	t.Run("nil address", func(t *testing.T) {
		tcp, err := NewTCP(TCPConfig{
			ListenAddr:     "127.0.0.1:0",
			MessageHandler: func(msg *ReceivedMessage) {},
		})
		if err != nil {
			t.Fatalf("NewTCP() error = %v", err)
		}
		defer tcp.Stop()

		if err := tcp.SendRaw([]byte{0x01}, nil); err != ErrInvalidAddress {
			t.Errorf("SendRaw() error = %v, want %v", err, ErrInvalidAddress)
		}
	})

	t.Run("send after close", func(t *testing.T) {
		tcp, err := NewTCP(TCPConfig{
			ListenAddr:     "127.0.0.1:0",
			MessageHandler: func(msg *ReceivedMessage) {},
		})
		if err != nil {
			t.Fatalf("NewTCP() error = %v", err)
		}
		tcp.Stop()

		addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:5540")
		if err := tcp.SendRaw([]byte{0x01}, addr); err != ErrClosed {
			t.Errorf("SendRaw() error = %v, want %v", err, ErrClosed)
		}
	})
}
