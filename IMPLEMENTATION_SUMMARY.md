# Matter-over-UDP Message Framing Implementation Summary

## Overview
This PR adds initial Matter-over-UDP message framing layer and minimal MRP (Message Reliability Protocol) ACK handling to enable future SecureChannel/PASE work.

## Implementation Status: ✅ Complete

### What Was Implemented

#### 1. New Package: `matter/protocol/mattermsg`
Full implementation of Matter message packet and exchange headers with encode/decode support.

**Key Features:**
- `PacketHeader` - Matter packet header (8+ bytes)
  - Session ID, security flags, message counter
  - Optional source/destination node IDs
  - Little-endian encoding
- `ExchangeHeader` - Exchange layer header (6+ bytes)
  - Exchange flags (Initiator, ACK, Reliability, Vendor, SecuredExtensions)
  - Opcode, exchange ID, protocol ID
  - Optional vendor ID and ACK counter
- `Message` - Complete message structure
  - Combines packet header + exchange header + payload
  - Full encode/decode with error handling
  - Debug-friendly String() with hex dumps

**Testing:**
- ✅ Roundtrip encode/decode tests
- ✅ Tests with captured payload fixtures
- ✅ Error handling for truncated messages
- ✅ All flag combinations validated

#### 2. New Package: `matter/protocol/mrp`
Minimal MRP support for standalone ACK handling.

**Key Features:**
- `BuildStandaloneAck()` - Creates ACK messages referencing received message counter
- `IsAckRequested()` - Detects reliability flag in messages
- `MessageCounter` - Thread-safe counter using atomic operations

**Testing:**
- ✅ ACK building validated
- ✅ ACK detection tests
- ✅ Thread-safe counter tests
- ✅ Roundtrip encode/decode of ACKs

#### 3. New Package: `matter/transport/matterudp`
Codec wrapper providing automatic framing and MRP ACK handling.

**Key Features:**
- Wraps `io.Transport` with message framing
- Auto-decode incoming messages
- Auto-send standalone ACK when reliability flag is set
- Message counter tracking
- Debug logging for all decoded headers
- Backward compatibility methods (TransmitBytes/ReceiveBytes)

**Testing:**
- ✅ Transmit/receive tests
- ✅ Auto-ACK behavior validated
- ✅ Counter increment tests
- ✅ Mock transport integration

#### 4. Enhanced: `matter/device_mdns.go`
IPv6 link-local address support with zone detection.

**Key Features:**
- Address preference order:
  1. IPv6 link-local (fe80::/10) with Zone
  2. IPv6 global
  3. IPv4 (fallback)
- Smart interface detection for link-local zones
- Backward compatible with existing IPv4-only setups

**Testing:**
- ✅ Builds without errors
- ✅ Existing mDNS tests unaffected

### Documentation
- ✅ Comprehensive README.md in matter/protocol/
- ✅ Inline code comments in English
- ✅ API documentation with examples

### Code Quality
- ✅ All tests passing (except pre-existing mDNS network permission issue)
- ✅ Code review completed - all issues addressed:
  - Fixed packet header flag bit positions per Matter spec
  - Made MessageCounter thread-safe with atomic operations
  - Improved IPv6 link-local zone detection logic
  - Fixed code style issues
- ✅ Security scan (CodeQL) - 0 vulnerabilities found
- ✅ Builds successfully (`go build ./...`)

## Test Results

```
ok  	matter/protocol/mattermsg	0.003s
ok  	matter/protocol/mrp	        0.003s
ok  	matter/transport/matterudp	0.003s
```

All 40+ test cases pass across the new packages.

## Usage Example

```go
// Create codec wrapper
transport := ... // raw io.Transport (UDP)
codec := matterudp.NewCodec(transport, true) // enable auto-ACK

// Receive message (auto-ACK if requested)
msg, err := codec.Receive(ctx)
if err != nil {
    log.Fatalf("Receive failed: %v", err)
}
log.Printf("Received: %s", msg.String())

// Send message with reliability flag
outMsg := &mattermsg.Message{
    PacketHeader: &mattermsg.PacketHeader{
        SessionID:      0x0000,
        MessageCounter: codec.NextMessageCounter(),
    },
    ExchangeHeader: &mattermsg.ExchangeHeader{
        ExchangeFlags: mattermsg.ExchangeFlagInitiator | 
                      mattermsg.ExchangeFlagReliability,
        Opcode:        0x20, // PBKDFParamRequest
        ExchangeID:    0x1234,
        ProtocolID:    0x0000, // SecureChannel
    },
    Payload: tlvData,
}
codec.Transmit(ctx, outMsg)
```

## What This Enables

This implementation provides the foundation for:
1. ✅ Proper Matter message framing over UDP
2. ✅ Standalone ACK support for reliable messaging
3. ✅ IPv6 link-local device discovery and connection
4. 🔜 SecureChannel protocol implementation
5. 🔜 PASE (Password-Authenticated Session Establishment)
6. 🔜 Full SPAKE2+ cryptographic handshake

## Non-Goals (Future Work)
- Full SecureChannel PBKDFParamRequest/Response implementation
- Complete SPAKE2+ implementation
- Full MRP retry logic with timeouts
- Session management and key derivation

## References
- Matter Core Specification 1.5, Section 4.7 (Message Layer)
- Matter Core Specification 1.5, Section 4.11 (Exchange Layer)
- Matter Core Specification 1.5, Section 4.11.8 (MRP)
