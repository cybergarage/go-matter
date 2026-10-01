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

package im

import (
	"fmt"
	"slices"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// ServeGroupMessage serves a decrypted message sent to a group whose
// members on this node are endpoints: each command of an InvokeRequest
// runs on every member endpoint which serves it, or on the one the
// command names if it is a member, with access checked for sess, which
// stands for the group. A group message is never answered.
// Other interactions are not served to groups.
func (s *Server) ServeGroupMessage(sess SecureSession, raw []byte, endpoints []EndpointID) error {
	protHdr, err := message.NewProtocolHeaderFromBytes(raw)
	if err != nil {
		return fmt.Errorf("im: group message: %w", err)
	}
	hdrBytes, err := protHdr.Bytes()
	if err != nil {
		return err
	}
	if protHdr.ProtocolID() != message.InteractionModel || protHdr.Opcode() != message.InvokeRequestMessage {
		log.Debugf("im: group message: ignore protocol 0x%04X opcode 0x%02X", uint16(protHdr.ProtocolID()), uint8(protHdr.Opcode()))
		return nil
	}
	req, err := decodeInvokeRequest(raw[len(hdrBytes):])
	if err != nil {
		return fmt.Errorf("im: group InvokeRequest: %w", err)
	}
	for _, cmd := range req.commands {
		targets := endpoints
		if !cmd.anyEndpoint {
			if !slices.Contains(endpoints, cmd.Endpoint) {
				continue
			}
			targets = []EndpointID{cmd.Endpoint}
		}
		for _, ep := range targets {
			entry, _ := s.commandHandler(commandPath{ep, cmd.Cluster, cmd.Command})
			if entry.handler == nil || !s.allowed(sess, ep, cmd.Cluster, entry.privilege) {
				continue
			}
			run := *cmd
			run.Session = sess
			run.Endpoint = ep
			run.anyEndpoint = false
			run.Timed = false
			result := entry.handler(&run)
			if result.AfterResponse != nil {
				result.AfterResponse()
			}
		}
	}
	return nil
}
