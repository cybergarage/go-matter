// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pase

import (
	"encoding/binary"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// Status codes PASE reports with (Matter Core 4.11.3, 4.14.1.2).
const (
	statusGeneralSuccess          uint16 = 0
	statusGeneralFailure          uint16 = 1
	statusProtocolSessionSuccess  uint16 = 0
	statusProtocolInvalidParamter uint16 = 2
)

// newStatusReport builds a Secure Channel StatusReport answering req, on
// req's exchange. Its payload is the fixed-width little-endian structure
// Initiator.parseStatusReport reads, not TLV.
func newStatusReport(req message.Message, headerOpts []message.HeaderOption, flags message.ExchangeFlag, generalCode, protocolCode uint16) message.Message {
	payload := make([]byte, statusReportHeaderLen)
	binary.LittleEndian.PutUint16(payload[0:2], generalCode)
	binary.LittleEndian.PutUint32(payload[2:6], uint32(message.SecureChannel))
	binary.LittleEndian.PutUint16(payload[6:8], protocolCode)

	return message.NewMessage(
		message.WithMessageFrameHeader(message.NewHeader(append([]message.HeaderOption{
			message.WithHeaderSessionID(0),
			message.WithHeaderSecurityFlags(0x00),
		}, headerOpts...)...)),
		message.WithMessageProtocolHeader(message.NewProtocolHeader(
			message.WithHeaderExchangeFlags(flags),
			message.WithHeaderOpcode(message.StatusReport),
			message.WithHeaderExchangeID(req.ExchangeID()),
			message.WithHeaderProtocolID(message.SecureChannel),
			message.WithHeaderAckCounter(req.MessageCounter()),
		)),
		message.WithMessagePayload(payload),
	)
}
