// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package caseprotocol

import (
	"context"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

type recordingTransport struct{ sent [][]byte }

func (t *recordingTransport) Transmit(_ context.Context, b []byte) error {
	t.sent = append(t.sent, append([]byte(nil), b...))
	return nil
}

func (t *recordingTransport) Receive(context.Context) ([]byte, error) { return nil, context.Canceled }

func buildSigmaFinishedForTest(t *testing.T, flags message.ExchangeFlag) (message.Message, []byte) {
	t.Helper()
	msg := message.NewMessage(
		message.WithMessageFrameHeader(message.NewHeader(
			message.WithHeaderSessionID(0),
			message.WithHeaderSecurityFlags(0x00),
			message.WithHeaderMessageCounter(message.NewMessageCounter()),
			message.WithHeaderSourceNodeID(0xB6C144BE822A44BA),
		)),
		message.WithMessageProtocolHeader(message.NewProtocolHeader(
			message.WithHeaderExchangeFlags(flags),
			message.WithHeaderOpcode(message.StatusReport),
			message.WithHeaderExchangeID(0xEB22),
			message.WithHeaderProtocolID(message.SecureChannel),
		)),
		message.WithMessagePayload(make([]byte, statusReportHeaderLen)),
	)
	b, err := msg.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return msg, b
}

// TestAckReliableAcknowledgesSigmaFinished: a device retransmits a
// SigmaFinished nobody acknowledged (4.12.7.1), which a real device did.
func TestAckReliableAcknowledgesSigmaFinished(t *testing.T) {
	msg, raw := buildSigmaFinishedForTest(t, message.ReliabilityFlag)
	tr := &recordingTransport{}
	if err := ackReliable(context.Background(), tr, raw, 0x1122); err != nil {
		t.Fatal(err)
	}
	if len(tr.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(tr.sent))
	}
	ack, err := message.NewMessageFromBytes(tr.sent[0])
	if err != nil {
		t.Fatal(err)
	}
	if !ack.Opcode().IsMRPStandaloneAck() || ack.IsReliability() || ack.ExchangeID() != msg.ExchangeID() || ack.SessionID() != 0 {
		t.Fatalf("not a standalone ACK on the exchange: %s", ack)
	}
	if !ack.ExchangeFlags().IsInitiator() {
		t.Fatal("the initiator's ACK must carry the initiator flag")
	}
	if counter, ok := ack.AckMessageCounter(); !ok || counter != msg.MessageCounter() {
		t.Fatalf("ACK counter %v, %v; want %v", counter, ok, msg.MessageCounter())
	}
	if dst, ok := ack.DestinationNodeID(); !ok || dst != 0xB6C144BE822A44BA {
		t.Fatalf("ACK destination %v, %v", dst, ok)
	}
}

func TestAckReliableLeavesUnreliableMessages(t *testing.T) {
	_, raw := buildSigmaFinishedForTest(t, 0)
	tr := &recordingTransport{}
	if err := ackReliable(context.Background(), tr, raw, 0x1122); err != nil {
		t.Fatal(err)
	}
	if len(tr.sent) != 0 {
		t.Fatal("an unreliable message must not be acknowledged")
	}
}
