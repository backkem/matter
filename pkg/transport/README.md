# transport

Package `transport` implements the network transport layer for Matter.

It abstracts the underlying network protocols (UDP, TCP) and provides a unified interface for sending and receiving Matter messages.

## Supported Transports

*   **UDP** (Default/Mandatory): Connectionless, used for discovery, group casting, and most operational messaging.
*   **TCP** (Optional): Connection-oriented, used for large data transfers (e.g., OTA).

## Architecture

The `Manager` owns the sockets and dispatches incoming messages to a registered handler.

```
      Application / Exchange Manager
                   ▲
                   │ OnMessageReceived ()
                   │
           ┌───────┴───────┐
           │    Manager    │
           └───────┬───────┘
                   │
       ┌───────────┴───────────┐
       ▼                       ▼
    ┌─────┐                 ┌─────┐
    │ UDP │                 │ TCP │
    └─────┘                 └─────┘
```

## Usage

### Initialize and Start

```go
import "github.com/backkem/matter/pkg/transport"

// Define the handler for incoming messages
handler := func(msg *transport.ReceivedMessage) {
    fmt.Printf("Received %d bytes from %s\n", len(msg.Data), msg.PeerAddr)
}

// Create manager (binds to port 5540 by default)
mgr, err := transport.NewManager(transport.ManagerConfig{
    MessageHandler: handler,
})

// Start listening
mgr.Start()
```

### Send a Message

The `Send` method automatically selects UDP or TCP based on the `PeerAddress`.

```go
// Send via UDP
addr := transport.NewUDPPeerAddress(remoteNetAddr)
err := mgr.Send(data, addr)
```

```