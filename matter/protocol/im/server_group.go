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
// members on this node are endpoints, with access checked for sess, which
// stands for the group. Each command of an InvokeRequest runs, and each
// attribute of a WriteRequest is written, on every member endpoint which
// serves it, or on the one the path names if it is a member. A group
// message is never answered. Other interactions are not served to groups.
func (s *Server) ServeGroupMessage(sess SecureSession, raw []byte, endpoints []EndpointID) error {
	protHdr, err := message.NewProtocolHeaderFromBytes(raw)
	if err != nil {
		return fmt.Errorf("im: group message: %w", err)
	}
	hdrBytes, err := protHdr.Bytes()
	if err != nil {
		return err
	}
	if protHdr.ProtocolID() != message.InteractionModel {
		log.Debugf("im: group message: ignore protocol 0x%04X", uint16(protHdr.ProtocolID()))
		return nil
	}
	body := raw[len(hdrBytes):]
	switch protHdr.Opcode() {
	case message.InvokeRequestMessage:
		return s.serveGroupInvoke(sess, body, endpoints)
	case message.WriteRequestMessage:
		return s.serveGroupWrite(sess, body, endpoints)
	default:
		log.Debugf("im: group message: ignore opcode 0x%02X", uint8(protHdr.Opcode()))
		return nil
	}
}

// groupTargets returns the endpoints a path of a group message names: the
// group's members when it names none, or the one it names if a member.
func groupTargets(endpoint *EndpointID, endpoints []EndpointID) []EndpointID {
	if endpoint == nil {
		return endpoints
	}
	if slices.Contains(endpoints, *endpoint) {
		return []EndpointID{*endpoint}
	}
	return nil
}

func (s *Server) serveGroupInvoke(sess SecureSession, body []byte, endpoints []EndpointID) error {
	req, err := decodeInvokeRequest(body)
	if err != nil {
		return fmt.Errorf("im: group InvokeRequest: %w", err)
	}
	for _, cmd := range req.commands {
		var named *EndpointID
		if !cmd.anyEndpoint {
			named = &cmd.Endpoint
		}
		for _, ep := range groupTargets(named, endpoints) {
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

// serveGroupWrite writes the attributes of a group's WriteRequest. A list
// written in chunks keeps the access its first chunk was granted, as a
// unicast write does; a write which fails is not reported to anyone.
func (s *Server) serveGroupWrite(sess SecureSession, body []byte, endpoints []EndpointID) error {
	writes, _, err := decodeWriteRequest(body)
	if err != nil {
		return fmt.Errorf("im: group WriteRequest: %w", err)
	}
	checked := map[AttributePath]bool{}
	for _, w := range writes {
		if w.path.cluster == nil || w.path.attribute == nil {
			continue
		}
		for _, ep := range groupTargets(w.path.endpoint, endpoints) {
			concrete := w
			concrete.path.endpoint = &ep
			if status := s.write(sess, concrete, false, checked); status != StatusSuccess {
				log.Debugf("im: group write of %d/0x%04X/0x%04X: status 0x%02X", ep, *w.path.cluster, *w.path.attribute, uint8(status))
			}
		}
	}
	return nil
}
