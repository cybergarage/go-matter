package caseprotocol

import (
	"encoding/binary"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// statusReportHeaderLen is the fixed-width portion of a StatusReport payload:
// GeneralCode (2 bytes) || ProtocolId (4 bytes) || ProtocolCode (2 bytes).
const statusReportHeaderLen = 8

// parseStatusReport parses a received StatusReport message and returns an
// error if the general code indicates failure.
//
// StatusReport is NOT TLV-encoded: its payload is a fixed-width,
// little-endian binary structure (see connectedhomeip's
// src/protocols/secure_channel/StatusReport.cpp, StatusReport::Parse):
//
//	uint16 GeneralCode
//	uint32 ProtocolId
//	uint16 ProtocolCode
//	octet  ProtocolData[] (optional, protocol-specific)
func parseStatusReport(data []byte) error {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return fmt.Errorf("case: parse status report: %w", err)
	}
	if !msg.Opcode().IsStatusReport() {
		return fmt.Errorf("case: expected StatusReport, got opcode 0x%02x", uint8(msg.Opcode()))
	}
	payload := msg.Payload()
	if len(payload) < statusReportHeaderLen {
		return fmt.Errorf("case: StatusReport: payload too short (%d bytes, want at least %d)", len(payload), statusReportHeaderLen)
	}
	generalCode := binary.LittleEndian.Uint16(payload[0:2])
	protocolCode := binary.LittleEndian.Uint16(payload[6:8])
	if generalCode != 0 {
		return fmt.Errorf("%w: protocol code %d", errStatusReport, protocolCode)
	}
	return nil
}
