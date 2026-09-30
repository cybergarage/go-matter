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
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// CommandRequest is one command of an InvokeRequestMessage, as a
// CommandHandler receives it.
type CommandRequest struct {
	// Session is the session the command arrived on, which a handler
	// needs for the attestation challenge, or to tell a PASE session from
	// a CASE one.
	Session SecureSession
	// Endpoint, Cluster and Command name the command.
	Endpoint EndpointID
	Cluster  ClusterID
	Command  CommandID
	// Fields holds the top-level command fields keyed by context tag. A
	// field which is itself a container is present as its container
	// element; Elements holds its contents.
	Fields map[uint8]tlv.Element
	// Elements holds every element inside the command fields, nested ones
	// included, in order, for the commands whose fields nest.
	Elements []tlv.Element
	// Timed reports whether the command arrived in a timed interaction.
	Timed bool
}

// Field returns the command field with the given context tag.
func (r *CommandRequest) Field(tag uint8) (tlv.Element, bool) {
	elem, ok := r.Fields[tag]
	return elem, ok
}

// CommandResult is what a CommandHandler answers a command with: either a
// response command with its fields, or a status.
type CommandResult struct {
	// ResponseCommand and Fields are the response command. Fields is a
	// single TLV structure tagged ContextTag(1), as built for im.Invoke.
	ResponseCommand CommandID
	Fields          []byte
	HasResponse     bool
	// Status is the status to answer with when there is no response
	// command. ClusterStatus is the cluster-specific status, if any.
	Status        Status
	ClusterStatus *uint8
	// AfterResponse, when not nil, is called once the response has been
	// sent, for what must not happen before, such as closing the session
	// the command arrived on.
	AfterResponse func()
}

// CommandResponse returns the result which answers with response command
// cmd and its fields.
func CommandResponse(cmd CommandID, fields []byte) CommandResult {
	return CommandResult{ResponseCommand: cmd, Fields: fields, HasResponse: true, Status: StatusSuccess, ClusterStatus: nil, AfterResponse: nil}
}

// CommandStatus returns the result which answers with status.
func CommandStatus(status Status) CommandResult {
	return CommandResult{ResponseCommand: 0, Fields: nil, HasResponse: false, Status: status, ClusterStatus: nil, AfterResponse: nil}
}

// CommandClusterStatus returns the result which answers with status and a
// cluster-specific status.
func CommandClusterStatus(status Status, clusterStatus uint8) CommandResult {
	return CommandResult{ResponseCommand: 0, Fields: nil, HasResponse: false, Status: status, ClusterStatus: &clusterStatus, AfterResponse: nil}
}

// CommandHandler handles one command.
type CommandHandler func(req *CommandRequest) CommandResult

// AttributeReader writes an attribute's value into a report. It encodes the
// value as one element with the given tag, and returns a status other than
// StatusSuccess to report that status instead.
type AttributeReader func(enc tlv.Encoder, tag tlv.Tag) Status

// AttributeRequest is the read of one attribute, as an
// AttributeReadHandler receives it.
type AttributeRequest struct {
	// Session is the session the read arrived on, which a fabric-scoped
	// attribute reports for.
	Session SecureSession
	// Path is the attribute read.
	Path AttributePath
	// FabricFiltered reports whether the peer asked only for the entries
	// of its own fabric of a fabric-scoped list (8.4.3.2).
	FabricFiltered bool
}

// AttributeReadHandler is an AttributeReader which knows the read it
// answers, for the attributes which depend on the session.
type AttributeReadHandler func(req *AttributeRequest, enc tlv.Encoder, tag tlv.Tag) Status

type commandEntry struct {
	handler   CommandHandler
	privilege Privilege
	generated []CommandID
}

type attributeEntry struct {
	handler   AttributeReadHandler
	privilege Privilege
}

type commandPath struct {
	endpoint EndpointID
	cluster  ClusterID
	command  CommandID
}

// AttributePath names one attribute.
type AttributePath struct {
	Endpoint  EndpointID
	Cluster   ClusterID
	Attribute AttributeID
}

// Server is an Interaction Model server: it answers the Invoke and Read
// interactions a peer sends over a secure session with the command
// handlers and attribute readers registered with it (Matter Core 8).
//
// It answers a Read with a single ReportDataMessage, so it cannot report
// more data than fits in one message, and it answers the other
// interactions (Write, Subscribe) with a StatusResponse of
// StatusInvalidAction.
type Server struct {
	mutex      sync.RWMutex
	commands   map[commandPath]commandEntry
	attributes map[AttributePath]attributeEntry
	access     AccessChecker
}

// NewServer returns a Server with nothing registered.
func NewServer() *Server {
	return &Server{
		mutex:      sync.RWMutex{},
		commands:   map[commandPath]commandEntry{},
		attributes: map[AttributePath]attributeEntry{},
		access:     nil,
	}
}

// SetAccessChecker sets the checker every request is subject to, with the
// privilege its handler requires; a request it refuses is answered with
// StatusUnsupportedAccess, and a wildcard read leaves out the attributes
// it refuses (8.4.3.2).
func (s *Server) SetAccessChecker(c AccessChecker) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.access = c
}

// HandleCommand registers h for a command, replacing any previous handler.
// It requires DefaultInvokePrivilege unless WithPrivilege says otherwise.
func (s *Server) HandleCommand(endpoint EndpointID, cluster ClusterID, command CommandID, h CommandHandler, opts ...HandlerOption) {
	o := newHandlerOptions(DefaultInvokePrivilege, opts)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.commands[commandPath{endpoint, cluster, command}] = commandEntry{handler: h, privilege: o.privilege, generated: o.generated}
	s.ensureGlobalAttributesLocked(endpoint, cluster)
}

// HandleAttribute registers r for an attribute, replacing any previous
// reader. It requires DefaultReadPrivilege unless WithPrivilege says
// otherwise.
func (s *Server) HandleAttribute(endpoint EndpointID, cluster ClusterID, attribute AttributeID, r AttributeReader, opts ...HandlerOption) {
	s.HandleAttributeRead(endpoint, cluster, attribute, func(_ *AttributeRequest, enc tlv.Encoder, tag tlv.Tag) Status {
		return r(enc, tag)
	}, opts...)
}

// HandleAttributeRead registers h for an attribute, replacing any previous
// reader, as HandleAttribute does for a reader which needs the request.
func (s *Server) HandleAttributeRead(endpoint EndpointID, cluster ClusterID, attribute AttributeID, h AttributeReadHandler, opts ...HandlerOption) {
	o := newHandlerOptions(DefaultReadPrivilege, opts)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.attributes[AttributePath{Endpoint: endpoint, Cluster: cluster, Attribute: attribute}] = attributeEntry{handler: h, privilege: o.privilege}
	s.ensureGlobalAttributesLocked(endpoint, cluster)
}

// allowed reports whether the access checker grants sess privilege on the
// cluster at the endpoint.
func (s *Server) allowed(sess SecureSession, endpoint EndpointID, cluster ClusterID, privilege Privilege) bool {
	s.mutex.RLock()
	access := s.access
	s.mutex.RUnlock()
	if access == nil {
		return true
	}
	return access(AccessRequest{Session: sess, Endpoint: endpoint, Cluster: cluster, Privilege: privilege})
}

// Serve answers the interactions arriving on sess until receiving fails,
// such as when the session's transport is closed, and returns that error.
// An interaction which cannot be decoded is logged and skipped.
func (s *Server) Serve(sess SecureSession) error {
	for {
		if err := s.ServeOne(sess); err != nil {
			var decodeErr *decodeError
			if errors.As(err, &decodeErr) {
				log.Warnf("im: server: %v", err)
				continue
			}
			return err
		}
	}
}

// decodeError marks a request the server could not decode, which Serve
// skips instead of stopping.
type decodeError struct {
	err error
}

func (e *decodeError) Error() string { return e.err.Error() }
func (e *decodeError) Unwrap() error { return e.err }

// ServeOne receives one message on sess and answers it.
func (s *Server) ServeOne(sess SecureSession) error {
	raw, err := sess.Receive()
	if err != nil {
		return err
	}
	protHdr, err := message.NewProtocolHeaderFromBytes(raw)
	if err != nil {
		return &decodeError{fmt.Errorf("im: parse protocol header: %w", err)}
	}
	hdrBytes, err := protHdr.Bytes()
	if err != nil {
		return &decodeError{err}
	}
	if len(raw) < len(hdrBytes) {
		return &decodeError{errors.New("im: message shorter than its protocol header")}
	}
	if protHdr.ProtocolID() != message.InteractionModel {
		log.Debugf("im: server: ignore protocol 0x%04X opcode 0x%02X", uint16(protHdr.ProtocolID()), uint8(protHdr.Opcode()))
		return nil
	}
	body := raw[len(hdrBytes):]
	exchange := protHdr.ExchangeID()

	switch protHdr.Opcode() {
	case message.InvokeRequestMessage:
		return s.serveInvoke(sess, exchange, body)
	case message.ReadRequestMessage:
		return s.serveRead(sess, exchange, body)
	case message.TimedRequestMessage:
		// The timeout is not enforced; the following request on the
		// exchange is accepted as timed.
		return sendStatusResponse(sess, exchange, StatusSuccess)
	case message.StatusResponseMessage:
		// The peer's acknowledgement of a report; nothing to answer.
		return nil
	default:
		return sendStatusResponse(sess, exchange, StatusInvalidAction)
	}
}

func (s *Server) commandHandler(p commandPath) (commandEntry, Status) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if e, ok := s.commands[p]; ok {
		return e, StatusSuccess
	}
	endpointKnown, clusterKnown := false, false
	for known := range s.commands {
		if known.endpoint == p.endpoint {
			endpointKnown = true
			if known.cluster == p.cluster {
				clusterKnown = true
			}
		}
	}
	for known := range s.attributes {
		if known.Endpoint == p.endpoint {
			endpointKnown = true
			if known.Cluster == p.cluster {
				clusterKnown = true
			}
		}
	}
	switch {
	case !endpointKnown:
		return commandEntry{handler: nil, privilege: 0, generated: nil}, StatusUnsupportedEndpoint
	case !clusterKnown:
		return commandEntry{handler: nil, privilege: 0, generated: nil}, StatusUnsupportedCluster
	default:
		return commandEntry{handler: nil, privilege: 0, generated: nil}, StatusUnsupportedCommand
	}
}

func (s *Server) serveInvoke(sess SecureSession, exchange message.ExchangeID, body []byte) error {
	req, err := decodeInvokeRequest(body)
	if err != nil {
		if sendErr := sendStatusResponse(sess, exchange, StatusInvalidAction); sendErr != nil {
			return sendErr
		}
		return &decodeError{fmt.Errorf("im: decode InvokeRequest: %w", err)}
	}
	results := make([]invokeResult, 0, len(req.commands))
	for _, cmd := range req.commands {
		cmd.Session = sess
		cmd.Timed = req.timed
		entry, status := s.commandHandler(commandPath{cmd.Endpoint, cmd.Cluster, cmd.Command})
		result := CommandStatus(status)
		switch {
		case entry.handler == nil:
		case !s.allowed(sess, cmd.Endpoint, cmd.Cluster, entry.privilege):
			result = CommandStatus(StatusUnsupportedAccess)
		default:
			result = entry.handler(cmd)
		}
		results = append(results, invokeResult{path: commandPath{cmd.Endpoint, cmd.Cluster, cmd.Command}, result: result})
	}
	defer func() {
		for _, r := range results {
			if r.result.AfterResponse != nil {
				r.result.AfterResponse()
			}
		}
	}()
	if req.suppressResponse {
		return nil
	}
	payload, err := encodeInvokeResponse(results)
	if err != nil {
		return err
	}
	return sendIMResponse(sess, exchange, message.InvokeResponseMessage, payload)
}

// expand returns the registered attribute paths which match a requested
// path, where nil fields are wildcards, and the status to report for a
// concrete path which matches none.
func (s *Server) expand(p requestedPath) ([]AttributePath, Status) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	var paths []AttributePath
	endpointKnown, clusterKnown := false, false
	for known := range s.attributes {
		if p.endpoint != nil && known.Endpoint != *p.endpoint {
			continue
		}
		endpointKnown = true
		if p.cluster != nil && known.Cluster != *p.cluster {
			continue
		}
		clusterKnown = true
		if p.attribute != nil && known.Attribute != *p.attribute {
			continue
		}
		paths = append(paths, known)
	}
	sort.Slice(paths, func(i, j int) bool {
		a, b := paths[i], paths[j]
		if a.Endpoint != b.Endpoint {
			return a.Endpoint < b.Endpoint
		}
		if a.Cluster != b.Cluster {
			return a.Cluster < b.Cluster
		}
		return a.Attribute < b.Attribute
	})
	if 0 < len(paths) || !p.concrete() {
		return paths, StatusSuccess
	}
	switch {
	case !endpointKnown:
		return nil, StatusUnsupportedEndpoint
	case !clusterKnown:
		return nil, StatusUnsupportedCluster
	default:
		return nil, StatusUnsupportedAttribute
	}
}

func (s *Server) attribute(p AttributePath) attributeEntry {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.attributes[p]
}

func (s *Server) serveRead(sess SecureSession, exchange message.ExchangeID, body []byte) error {
	paths, fabricFiltered, err := decodeReadRequest(body)
	if err != nil {
		if sendErr := sendStatusResponse(sess, exchange, StatusInvalidAction); sendErr != nil {
			return sendErr
		}
		return &decodeError{fmt.Errorf("im: decode ReadRequest: %w", err)}
	}
	reports := make([]attributeReport, 0, len(paths))
	for _, p := range paths {
		expanded, status := s.expand(p)
		if status != StatusSuccess {
			reports = append(reports, attributeReport{path: p.concretePath(), status: status, read: nil})
			continue
		}
		for _, ap := range expanded {
			entry := s.attribute(ap)
			if !s.allowed(sess, ap.Endpoint, ap.Cluster, entry.privilege) {
				// A wildcard read leaves out what the subject may not
				// read; a concrete one reports it (8.4.3.2).
				if p.concrete() {
					reports = append(reports, attributeReport{path: ap, status: StatusUnsupportedAccess, read: nil})
				}
				continue
			}
			req := &AttributeRequest{Session: sess, Path: ap, FabricFiltered: fabricFiltered}
			handler := entry.handler
			read := func(enc tlv.Encoder, tag tlv.Tag) Status { return handler(req, enc, tag) }
			reports = append(reports, attributeReport{path: ap, status: StatusSuccess, read: read})
		}
	}
	payload, err := encodeReportData(reports)
	if err != nil {
		return err
	}
	return sendIMResponse(sess, exchange, message.ReportDataMessage, payload)
}

// sendIMResponse sends payload as a message of the given opcode on the
// peer's exchange: without the initiator flag, and asking for an ack.
func sendIMResponse(sess SecureSession, exchange message.ExchangeID, opcode message.Opcode, payload []byte) error {
	hdr, err := message.NewProtocolHeader(
		message.WithHeaderExchangeFlags(message.ReliabilityFlag),
		message.WithHeaderOpcode(opcode),
		message.WithHeaderExchangeID(exchange),
		message.WithHeaderProtocolID(message.InteractionModel),
	).Bytes()
	if err != nil {
		return err
	}
	return sess.Transmit(append(hdr, payload...))
}

// sendStatusResponse answers with a StatusResponseMessage (10.7.1).
func sendStatusResponse(sess SecureSession, exchange message.ExchangeID, status Status) error {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	enc.PutUnsigned1(tlv.NewContextTag(0), uint8(status))
	enc.PutUnsigned1(tlv.NewContextTag(interactionModelRevisionTag), interactionModelRevision)
	if err := enc.EndContainer(); err != nil {
		return err
	}
	return sendIMResponse(sess, exchange, message.StatusResponseMessage, enc.Bytes())
}
