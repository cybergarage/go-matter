package caseprotocol

import (
	"encoding/binary"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// statusReportHeaderLen is the fixed-width portion of a StatusReport payload:
// GeneralCode (2 bytes) || ProtocolId (4 bytes) || ProtocolCode (2 bytes).
const statusReportHeaderLen = 8

// generalStatusCodeNames maps SecureChannel::GeneralStatusCode
// (src/protocols/secure_channel/Constants.h) to its symbolic name, for
// readable errors instead of a bare integer.
var generalStatusCodeNames = map[uint16]string{
	0:  "SUCCESS",
	1:  "FAILURE",
	2:  "BAD_PRECONDITION",
	3:  "OUT_OF_RANGE",
	4:  "BAD_REQUEST",
	5:  "UNSUPPORTED",
	6:  "UNEXPECTED",
	7:  "RESOURCE_EXHAUSTED",
	8:  "BUSY",
	9:  "TIMEOUT",
	10: "CONTINUE",
	11: "ABORTED",
	12: "INVALID_ARGUMENT",
	13: "NOT_FOUND",
	14: "ALREADY_EXISTS",
	15: "PERMISSION_DENIED",
	16: "DATA_LOSS",
}

// secureChannelProtocolCodeNames maps the SecureChannel protocol's own
// protocol-specific codes (src/protocols/secure_channel/Constants.h
// kProtocolCode*) to their symbolic names. Only meaningful when protocolID
// is the SecureChannel protocol (0x0000); other protocols define their own
// code spaces.
var secureChannelProtocolCodeNames = map[uint16]string{
	0x0000: "SUCCESS",
	0x0001: "NO_SHARED_TRUST_ROOTS",
	0x0002: "INVALID_PARAMETER",
	0x0003: "CLOSE_SESSION",
	0x0004: "BUSY",
	0xFFFF: "GENERAL_FAILURE",
}

// statusReport is the parsed form of a received StatusReport message.
type statusReport struct {
	generalCode  uint16
	protocolID   uint32
	protocolCode uint16
}

func (s statusReport) String() string {
	generalName := generalStatusCodeNames[s.generalCode]
	if generalName == "" {
		generalName = "UNKNOWN"
	}
	protocolName := ""
	if s.protocolID == 0x0000 {
		protocolName = secureChannelProtocolCodeNames[s.protocolCode]
	}
	if protocolName == "" {
		protocolName = "UNKNOWN"
	}
	return fmt.Sprintf("generalCode=%d(%s) protocolID=0x%08X protocolCode=%d(%s)",
		s.generalCode, generalName, s.protocolID, s.protocolCode, protocolName)
}

// decodeStatusReport parses a StatusReport message's payload.
//
// StatusReport is NOT TLV-encoded: its payload is a fixed-width,
// little-endian binary structure (see connectedhomeip's
// src/protocols/secure_channel/StatusReport.cpp, StatusReport::Parse):
//
//	uint16 GeneralCode
//	uint32 ProtocolId
//	uint16 ProtocolCode
//	octet  ProtocolData[] (optional, protocol-specific)
func decodeStatusReport(msg message.Message) (statusReport, error) {
	if !msg.Opcode().IsStatusReport() {
		return statusReport{}, fmt.Errorf("case: expected StatusReport, got opcode 0x%02x", uint8(msg.Opcode()))
	}
	payload := msg.Payload()
	if len(payload) < statusReportHeaderLen {
		return statusReport{}, fmt.Errorf("case: StatusReport: payload too short (%d bytes, want at least %d)", len(payload), statusReportHeaderLen)
	}
	return statusReport{
		generalCode:  binary.LittleEndian.Uint16(payload[0:2]),
		protocolID:   binary.LittleEndian.Uint32(payload[2:6]),
		protocolCode: binary.LittleEndian.Uint16(payload[6:8]),
	}, nil
}

// parseStatusReport parses a received StatusReport message and returns an
// error if the general code indicates failure.
func parseStatusReport(data []byte) error {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return fmt.Errorf("case: parse status report: %w", err)
	}
	sr, err := decodeStatusReport(msg)
	if err != nil {
		return err
	}
	if sr.generalCode != 0 {
		return fmt.Errorf("%w: %s", errStatusReport, sr)
	}
	return nil
}
