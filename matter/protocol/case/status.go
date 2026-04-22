package caseprotocol

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

func parseStatusReport(data []byte) error {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return fmt.Errorf("case: parse status report: %w", err)
	}
	if !msg.Opcode().IsStatusReport() {
		return fmt.Errorf("case: expected StatusReport, got opcode 0x%02x", uint8(msg.Opcode()))
	}
	dec := tlv.NewDecoderWithBytes(msg.Payload())
	if !dec.Next() {
		return fmt.Errorf("case: StatusReport: empty payload")
	}
	if !dec.Element().Type().IsStructure() {
		return fmt.Errorf("case: StatusReport: expected structure")
	}
	var generalCode uint16
	var protocolCode uint16
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		switch ct.ContextNumber() {
		case 0:
			generalCode, _ = elem.Unsigned2()
		case 2:
			protocolCode, _ = elem.Unsigned2()
		}
	}
	if generalCode != 0 {
		return fmt.Errorf("%w: protocol code %d", errStatusReport, protocolCode)
	}
	return nil
}
