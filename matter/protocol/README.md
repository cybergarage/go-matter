# Matter Message Framing and MRP Support

This directory contains the implementation of Matter-over-UDP message framing and minimal Message Reliability Protocol (MRP) support.

## Packages

### `matter/protocol/mattermsg`

Provides encoding and decoding for Matter message packet and exchange headers.

**Key types:**
- `PacketHeader` - Matter packet header with session ID, message counter, and optional node IDs
- `ExchangeHeader` - Exchange layer header with flags, opcode, exchange ID, protocol ID
- `Message` - Complete Matter message (packet header + exchange header + payload)

**Features:**
- Little-endian encoding/decoding
- Support for optional fields (source/dest node IDs, vendor ID, ACK counter)
- Clear error messages for truncated/invalid messages
- Debug-friendly String() methods with hex dumps

**Example:**
```go
// Decode a received message
msg, err := mattermsg.DecodeMessage(data)
if err != nil {
    log.Fatalf("Failed to decode: %v", err)
}

log.Printf("Received: %s", msg.String())

// Encode a message for transmission
outMsg := &mattermsg.Message{
    PacketHeader: &mattermsg.PacketHeader{
        SessionID: 0x0000,
        MessageCounter: counter,
    },
    ExchangeHeader: &mattermsg.ExchangeHeader{
        ExchangeFlags: mattermsg.ExchangeFlagInitiator | mattermsg.ExchangeFlagReliability,
        Opcode: 0x20,
        ExchangeID: 0x1234,
        ProtocolID: 0x0000,
    },
    Payload: tlvData,
}
encoded := outMsg.Encode()
```

### `matter/protocol/mrp`

Provides minimal Message Reliability Protocol (MRP) support for ACK handling.

**Key functions:**
- `BuildStandaloneAck()` - Create a standalone ACK message for a received message
- `IsAckRequested()` - Check if a message requests an ACK (reliability flag set)
- `MessageCounter` - Track outbound message counters

**Example:**
```go
// Check if ACK is needed
if mrp.IsAckRequested(receivedMsg) {
    // Build and send ACK
    ack := mrp.BuildStandaloneAck(receivedMsg, counter.Next())
    transport.Transmit(ctx, ack.Encode())
}
```

### `matter/transport/matterudp`

Provides a codec that wraps `io.Transport` to add automatic message framing and MRP ACK handling.

**Key types:**
- `Codec` - Wraps a raw transport with framing and auto-ACK support

**Features:**
- Automatic message encoding/decoding
- Optional automatic ACK sending when reliability is requested
- Message counter tracking
- Debug logging of decoded headers

**Example:**
```go
// Wrap a raw UDP transport
rawTransport := ... // implements io.Transport
codec := matterudp.NewCodec(rawTransport, true) // enable auto-ACK

// Send a message
msg := &mattermsg.Message{...}
codec.Transmit(ctx, msg)

// Receive a message (auto-ACK if requested)
receivedMsg, err := codec.Receive(ctx)
if err != nil {
    log.Fatalf("Receive failed: %v", err)
}

// Access next message counter
msgCounter := codec.NextMessageCounter()
```

## IPv6 Link-Local Support

The `device_mdns.go` has been updated to prefer IPv6 link-local addresses (fe80::/10) when connecting to devices discovered via mDNS. When using IPv6 link-local addresses, the Zone field (interface name) is automatically set based on interface enumeration.

**Address preference order:**
1. IPv6 link-local (with Zone set)
2. IPv6 global
3. IPv4

## Testing

All packages include comprehensive unit tests:

```bash
# Test message encoding/decoding
go test ./matter/protocol/mattermsg/...

# Test MRP ACK handling
go test ./matter/protocol/mrp/...

# Test codec wrapper
go test ./matter/transport/matterudp/...

# Run all tests
go test ./...
```

## References

- Matter Core Specification 1.5, Section 4.7 (Message Layer)
- Matter Core Specification 1.5, Section 4.11 (Exchange Layer)
- Matter Core Specification 1.5, Section 4.11.8 (MRP - Message Reliability Protocol)
