// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package caseprotocol provides CASE (Certificate Authenticated Session
// Establishment): the Initiator a commissioner finalizes commissioning over
// the operational network with, and the Responder a device answers it with.
package caseprotocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/credentials"
	mcrypto "github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/io"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// Transport is the underlying byte-oriented transport used for CASE.
type Transport = io.Transport

const (
	cryptoSymmetricKeyLen = 16
	randomLen             = 32
	resumptionIDLen       = 16
	signatureLen          = 64
	destinationIDLen      = 32
	ephPubKeyLen          = 65
)

// caseRetryAttempts / caseRetryInterval implement a minimal retransmission
// scheme for Sigma1 and Sigma3: both are sent with message.ReliabilityFlag
// set, meaning MRP requires the sender to retransmit if no timely response
// arrives, but Transport (a bare UDP socket) has no automatic retransmit
// timer of its own. Without this, a single UDP datagram lost to ordinary
// network conditions — observed against a real device, where nothing at all
// came back after Sigma1 — stalls receiveSkipAck until the entire remaining
// commissioning deadline (matter.DefaultCommissioningTimeout, ~120s)
// elapses, instead of retrying within a few seconds. Package-level vars
// (not consts) so tests can shrink caseRetryInterval instead of taking
// caseRetryAttempts*caseRetryInterval wall-clock seconds to exercise retry
// behavior.
var (
	caseRetryAttempts = 5
	caseRetryInterval = 3 * time.Second
)

// ErrUnexpectedResponder is returned when the responder's NOC does not name
// the node and the fabric the initiator asked for.
var ErrUnexpectedResponder = errors.New("case: unexpected responder")

var (
	errStatusReport = errors.New("case: status report indicates failure")
	sigma2Nonce     = []byte("NCASE_Sigma2N")
	sigma3Nonce     = []byte("NCASE_Sigma3N")
	sigma2Info      = []byte("Sigma2")
	sigma3Info      = []byte("Sigma3")
	sessionKeysInfo = []byte("SessionKeys")
)

// Option configures a CASE initiator.
type Option func(*Initiator)

// WithPeerNodeID sets the target operational node identifier used for Sigma1 destination ID.
func WithPeerNodeID(nodeID uint64) Option {
	return func(i *Initiator) {
		i.peerNodeID = nodeID
	}
}

// WithIPK sets the fabric IPK used for destination identifier and CASE KDF salts.
func WithIPK(ipk []byte) Option {
	return func(i *Initiator) {
		i.ipk = cloneBytes(ipk)
	}
}

// WithResumption asks to resume the session state names (4.14.2.2.1). The
// responder answers with Sigma2_Resume when it still has the session, and
// with a full Sigma2 otherwise, which the initiator then completes.
func WithResumption(state *ResumptionState) Option {
	return func(i *Initiator) {
		i.resumeFrom = state.clone()
	}
}

// Initiator represents a CASE client.
type Initiator struct {
	t          Transport
	cfg        config.AdministratorConfig
	peerNodeID uint64
	ipk        []byte
	// peerMRP are the MRP parameters of the responder's Sigma2.
	peerMRP session.MRPParameters
	// resumeFrom is the session to resume, if any; resumption is the state
	// to keep after EstablishSession, and resumed whether it resumed.
	resumeFrom *ResumptionState
	resumption *ResumptionState
	resumed    bool
}

// ResumptionState returns the state to resume the session EstablishSession
// established with, the next time; nil before it succeeds.
func (i *Initiator) ResumptionState() *ResumptionState {
	return i.resumption.clone()
}

// Resumed reports whether EstablishSession resumed a session rather than
// running a full CASE.
func (i *Initiator) Resumed() bool {
	return i.resumed
}

// NewInitiator creates a new CASE initiator.
func NewInitiator(t Transport, cfg config.AdministratorConfig, opts ...Option) *Initiator {
	i := &Initiator{
		t:       t,
		cfg:     cfg,
		peerMRP: session.DefaultMRPParameters(),
	}
	for _, opt := range opts {
		opt(i)
	}
	return i
}

// EstablishSession performs the non-resumption CASE Sigma1 / Sigma2 / Sigma3 exchange
// and returns session keys for the encrypted operational session.
func (i *Initiator) EstablishSession(ctx context.Context) (session.SessionKeys, error) {
	if i.t == nil {
		return nil, fmt.Errorf("case: transport is required")
	}
	inputs, err := loadAdministratorInputs(i.cfg)
	if err != nil {
		return nil, err
	}
	if i.peerNodeID == 0 {
		return nil, fmt.Errorf("case: peer node ID is required")
	}
	if len(i.ipk) == 0 {
		return nil, fmt.Errorf("case: IPK is required")
	}
	compressedFabricIDBytes, err := computeCompressedFabricIDBytes(inputs.rootPublicKey, inputs.fabricID)
	if err != nil {
		return nil, fmt.Errorf("case: compressed fabric ID: %w", err)
	}
	operationalIPK, err := deriveGroupOperationalKey(i.ipk, compressedFabricIDBytes)
	if err != nil {
		return nil, fmt.Errorf("case: derive operational IPK: %w", err)
	}

	initiatorRandom := make([]byte, randomLen)
	if _, err := rand.Read(initiatorRandom); err != nil {
		return nil, fmt.Errorf("case: initiator random: %w", err)
	}
	initiatorSessionID, err := newSessionID()
	if err != nil {
		return nil, fmt.Errorf("case: initiator session ID: %w", err)
	}

	ephPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("case: initiator ephemeral key: %w", err)
	}
	initiatorEphPubKey := elliptic.Marshal(elliptic.P256(), ephPriv.PublicKey.X, ephPriv.PublicKey.Y)
	destinationID := computeDestinationID(operationalIPK, initiatorRandom, inputs.rootPublicKey, inputs.fabricID, i.peerNodeID)
	log.Infof(
		"CASE target: peer_node_id=0x%016X destination_id=%s initiator_eph=%s",
		i.peerNodeID,
		redactedBytes(destinationID),
		redactedBytes(initiatorEphPubKey),
	)

	exchangeID := message.NewFirstExchangeID()
	s1 := sigma1{
		InitiatorRandom:    initiatorRandom,
		InitiatorSessionID: uint16(initiatorSessionID),
		DestinationID:      destinationID,
		InitiatorEphPubKey: initiatorEphPubKey,
	}
	if i.resumeFrom.valid() {
		mic, err := resumeMIC(i.resumeFrom.SharedSecret, initiatorRandom, i.resumeFrom.ResumptionID, sigma1ResumeInfo, sigma1ResumeNonce)
		if err != nil {
			return nil, err
		}
		s1.ResumptionID, s1.ResumeMIC = i.resumeFrom.ResumptionID, mic
	}
	sigma1Payload, err := encodeSigma1(s1)
	if err != nil {
		return nil, err
	}
	sigma1Msg, err := buildCASEMessage(message.CASESigma1, message.InitiatorFlag|message.ReliabilityFlag, exchangeID, message.NodeID(inputs.nodeID), sigma1Payload, false, 0)
	if err != nil {
		return nil, err
	}
	sigma1Bytes, err := sigma1Msg.Bytes()
	if err != nil {
		return nil, err
	}
	log.Infof("CASE Sigma1: session_id=0x%04X exchange_id=0x%04X payload=%s", initiatorSessionID, exchangeID, redactedBytes(sigma1Payload))
	log.HexDebug(sigma1Bytes)
	sigma2Raw, err := transmitAndReceiveWithRetry(ctx, i.t, exchangeID, sigma1Bytes)
	if err != nil {
		return nil, fmt.Errorf("case: transmit Sigma1 / receive Sigma2: %w", err)
	}
	sigma2Msg, err := message.NewMessageFromBytes(sigma2Raw)
	if err != nil {
		return nil, fmt.Errorf("case: parse Sigma2 message: %w", err)
	}
	if sigma2Msg.Opcode() == message.CASESigma2Resume && i.resumeFrom.valid() {
		return i.finishResumption(ctx, sigma2Msg, exchangeID, inputs.nodeID, initiatorRandom, initiatorSessionID)
	}
	if !sigma2Msg.Opcode().IsCASESigma2() {
		if sigma2Msg.Opcode().IsStatusReport() {
			if sr, srErr := decodeStatusReport(sigma2Msg); srErr == nil {
				return nil, fmt.Errorf("case: expected Sigma2, got StatusReport: %s", sr)
			}
		}
		return nil, fmt.Errorf("case: expected Sigma2, got opcode 0x%02x", uint8(sigma2Msg.Opcode()))
	}
	log.HexDebug(sigma2Msg.Payload())
	sigma2, err := decodeSigma2(sigma2Msg.Payload())
	if err != nil {
		log.Infof("CASE Sigma2: malformed payload")
		return nil, err
	}
	i.peerMRP = decodeMRPParameters(sigma2Msg.Payload(), 5)
	log.Infof(
		"CASE Sigma2: responder_session_id=0x%04X responder_random=%s responder_eph=%s encrypted2=%s",
		sigma2.ResponderSessionID,
		redactedBytes(sigma2.ResponderRandom),
		redactedBytes(sigma2.ResponderEphPubKey),
		redactedBytes(sigma2.Encrypted2),
	)

	sharedSecret, err := ecdhSharedSecret(ephPriv, sigma2.ResponderEphPubKey)
	if err != nil {
		return nil, fmt.Errorf("case: shared secret: %w", err)
	}
	s2k, err := deriveSigma2Key(sharedSecret, operationalIPK, sigma2.ResponderRandom, sigma2.ResponderEphPubKey, sigma1Msg.Payload())
	if err != nil {
		return nil, err
	}
	tbeData2Bytes, err := mcrypto.CryptoCCMDecrypt(s2k, sigma2Nonce, sigma2.Encrypted2, nil)
	if err != nil {
		log.Infof("CASE Sigma2: decrypt failed")
		return nil, fmt.Errorf("case: decrypt Sigma2 payload: %w", err)
	}
	tbeData2, err := decodeSigma2TBEData(tbeData2Bytes)
	if err != nil {
		log.Infof("CASE Sigma2: decrypted payload malformed")
		return nil, err
	}
	log.Infof(
		"CASE Sigma2: decrypted responder_noc=%s responder_icac=%s signature=%s",
		redactedBytes(tbeData2.ResponderNOC),
		redactedBytes(tbeData2.ResponderICAC),
		redactedBytes(tbeData2.Signature),
	)
	if err := verifyCertificateChain(tbeData2.ResponderNOC, tbeData2.ResponderICAC, inputs.rootCertificate); err != nil {
		log.Infof("CASE Sigma2: certificate validation failed")
		return nil, fmt.Errorf("case: verify responder certificate chain: %w", err)
	}
	log.Infof("CASE Sigma2: certificate validation ok")
	responderLeaf, err := parseCertificateBytes(tbeData2.ResponderNOC)
	if err != nil {
		return nil, err
	}
	if err := verifyResponderIdentity(responderLeaf, i.peerNodeID, inputs.fabricID); err != nil {
		log.Infof("CASE Sigma2: responder identity mismatch")
		return nil, err
	}
	sigma2TBS, err := encodeSigmaTBSData(tbeData2.ResponderNOC, tbeData2.ResponderICAC, sigma2.ResponderEphPubKey, initiatorEphPubKey)
	if err != nil {
		return nil, err
	}
	if !verifySignatureFromCert(responderLeaf, sigma2TBS, tbeData2.Signature) {
		log.Infof("CASE Sigma2: signature verification failed")
		return nil, fmt.Errorf("case: responder Sigma2 signature verification failed")
	}
	log.Infof("CASE Sigma2: signature verification ok")

	initiatorNOCTLV, initiatorICACTLV, err := chipCertTLVBytes(inputs.nocDER, inputs.icacDER)
	if err != nil {
		return nil, fmt.Errorf("case: encode initiator certificates: %w", err)
	}
	sigma3TBS, err := encodeSigmaTBSData(initiatorNOCTLV, initiatorICACTLV, initiatorEphPubKey, sigma2.ResponderEphPubKey)
	if err != nil {
		return nil, err
	}
	sigma3Sig, err := inputs.signer.Sign(sigma3TBS)
	if err != nil {
		return nil, fmt.Errorf("case: Sigma3 signature: %w", err)
	}
	sigma3TBEData, err := encodeSigma3TBEData(sigma3TBEData{
		InitiatorNOC:  initiatorNOCTLV,
		InitiatorICAC: initiatorICACTLV,
		Signature:     sigma3Sig,
	})
	if err != nil {
		return nil, err
	}
	s3k, err := deriveSigma3Key(sharedSecret, operationalIPK, sigma1Msg.Payload(), sigma2Msg.Payload())
	if err != nil {
		return nil, err
	}
	encrypted3, err := mcrypto.CryptoCCMEncrypt(s3k, sigma3Nonce, sigma3TBEData, nil)
	if err != nil {
		return nil, fmt.Errorf("case: encrypt Sigma3 payload: %w", err)
	}
	sigma3Payload, err := encodeSigma3(sigma3{Encrypted3: encrypted3})
	if err != nil {
		return nil, err
	}
	sigma3Msg, err := buildCASEMessage(message.CASESigma3, message.InitiatorFlag|message.ReliabilityFlag, exchangeID, message.NodeID(inputs.nodeID), sigma3Payload, true, sigma2Msg.MessageCounter())
	if err != nil {
		return nil, err
	}
	sigma3Bytes, err := sigma3Msg.Bytes()
	if err != nil {
		return nil, err
	}
	log.Infof("CASE Sigma3: encrypted3=%s", redactedBytes(encrypted3))
	log.HexDebug(sigma3Bytes)
	statusRaw, err := transmitAndReceiveWithRetry(ctx, i.t, exchangeID, sigma3Bytes)
	if err != nil {
		return nil, fmt.Errorf("case: transmit Sigma3 / receive SigmaFinished: %w", err)
	}
	if err := parseStatusReport(statusRaw); err != nil {
		log.Infof("CASE SigmaFinished: status failure")
		return nil, err
	}
	log.Infof("CASE SigmaFinished: success")

	sessionKeys, err := deriveSessionKeys(sharedSecret, operationalIPK, sigma1RawPayload(sigma1Msg), sigma2RawPayload(sigma2Msg), sigma3RawPayload(sigma3Msg), initiatorSessionID, session.SessionID(sigma2.ResponderSessionID), session.NodeID(inputs.nodeID), session.NodeID(i.peerNodeID))
	if err != nil {
		return nil, err
	}
	// The responder offered this session for resumption in Sigma2.
	i.resumption = &ResumptionState{ResumptionID: cloneBytes(tbeData2.ResumptionID), SharedSecret: cloneBytes(sharedSecret)}
	i.resumed = false
	return sessionKeys, nil
}

// finishResumption completes a resumed CASE (4.14.2.2.2): it checks the
// Sigma2_Resume's MIC with the new resumption ID, tells the responder it
// succeeded, and derives the session keys from the kept shared secret,
// salted with the resumption ID Sigma1 named.
func (i *Initiator) finishResumption(ctx context.Context, msg message.Message, exchangeID message.ExchangeID, localNodeID uint64, initiatorRandom []byte, initiatorSessionID session.SessionID) (session.SessionKeys, error) {
	resume, err := decodeSigma2Resume(msg.Payload())
	if err != nil {
		return nil, err
	}
	if err := verifyResumeMIC(resume.MIC, i.resumeFrom.SharedSecret, initiatorRandom, resume.ResumptionID, sigma2ResumeInfo, sigma2ResumeNonce); err != nil {
		return nil, fmt.Errorf("case: Sigma2_Resume: %w", err)
	}
	i.peerMRP = resume.ResponderMRP
	payload := make([]byte, statusReportHeaderLen)
	binary.LittleEndian.PutUint16(payload[0:2], statusGeneralSuccess)
	binary.LittleEndian.PutUint32(payload[2:6], uint32(message.SecureChannel))
	binary.LittleEndian.PutUint16(payload[6:8], statusProtocolSessionSuccess)
	reportMsg, err := buildCASEMessage(message.StatusReport, message.InitiatorFlag|message.ReliabilityFlag, exchangeID, message.NodeID(localNodeID), payload, true, msg.MessageCounter())
	if err != nil {
		return nil, err
	}
	reportBytes, err := reportMsg.Bytes()
	if err != nil {
		return nil, err
	}
	if err := transmitUntilAcked(ctx, i.t, exchangeID, reportBytes); err != nil {
		return nil, fmt.Errorf("case: transmit StatusReport after Sigma2_Resume: %w", err)
	}
	keys, err := deriveResumedSessionKeys(i.resumeFrom.SharedSecret, initiatorRandom, i.resumeFrom.ResumptionID,
		initiatorSessionID, session.SessionID(resume.ResponderSessionID), session.NodeID(localNodeID), session.NodeID(i.peerNodeID))
	if err != nil {
		return nil, err
	}
	log.Infof("CASE: resumed the session with node 0x%016X", i.peerNodeID)
	i.resumption = &ResumptionState{ResumptionID: cloneBytes(resume.ResumptionID), SharedSecret: cloneBytes(i.resumeFrom.SharedSecret)}
	i.resumed = true
	return keys, nil
}

// resumeAckAttempts bounds how many times the StatusReport which ends a
// resumed CASE is sent while no acknowledgement comes back.
const resumeAckAttempts = 3

// transmitUntilAcked sends a reliable message which expects no response,
// again while no acknowledgement arrives on the exchange, as MRP does
// (4.12). A message no acknowledgement came for is taken as delivered: the
// peer may acknowledge it only with its first message on the new session.
func transmitUntilAcked(ctx context.Context, t Transport, exchangeID message.ExchangeID, b []byte) error {
	for range resumeAckAttempts {
		if err := t.Transmit(ctx, b); err != nil {
			return err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, time.Second)
		acked := waitForAck(attemptCtx, t, exchangeID)
		cancel()
		if acked {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	log.Debugf("CASE: no acknowledgement of the StatusReport on exchange 0x%04X", exchangeID)
	return nil
}

// waitForAck reports whether a message acknowledging something on the
// exchange arrives before ctx ends.
func waitForAck(ctx context.Context, t Transport, exchangeID message.ExchangeID) bool {
	for {
		raw, err := t.Receive(ctx)
		if err != nil {
			return false
		}
		msg, err := message.NewMessageFromBytes(raw)
		if err != nil || msg.ExchangeID() != exchangeID {
			continue
		}
		if _, ok := msg.AckMessageCounter(); ok {
			return true
		}
	}
}

func redactedBytes(b []byte) string {
	if len(b) == 0 {
		return "len=0"
	}
	digest := mcrypto.CryptoHash(b)
	prefixLen := min(len(digest), 4)
	return fmt.Sprintf("len=%d sha256=%s", len(b), hex.EncodeToString(digest[:prefixLen]))
}

func sigma1RawPayload(msg message.Message) []byte { return cloneBytes(msg.Payload()) }
func sigma2RawPayload(msg message.Message) []byte { return cloneBytes(msg.Payload()) }
func sigma3RawPayload(msg message.Message) []byte { return cloneBytes(msg.Payload()) }

// buildCASEMessage builds an unsecured (SessionID 0) SecureChannel message
// for CASE, with sourceNodeID set as the Message Header's Source Node ID.
//
// This is not optional decoration: a real device silently dropped every
// Sigma1 this client sent — no response at all, not even a StatusReport,
// across multiple retries and independent of whether the connection reused
// PASE's own source port — until compared against a real, successful
// chip-tool run's own Sigma1 on the wire, which showed
// "Msg TX from 9A5B0ADD03226474 to 0:0000000000000000 ... CASE_Sigma1":
// chip-tool's commissioner included its own operational Node ID as the
// message's Source Node ID even though the session itself is unsecured.
// This client never set it at all, so the Source Node ID Present flag was
// never set either — a real device apparently requires it to even route
// the message to its CASE handler, rather than just rejecting it with an
// error response.
//
// ackMessageCounter/hasAck acknowledge a previously received message (e.g.
// Sigma3 acknowledging Sigma2), via message.WithHeaderAckCounter — not an
// optional courtesy: the caller previously set message.AckFlag directly in
// flags without ever supplying the counter it acknowledges, so the wire
// message claimed to ack message counter 0. A real device's MRP layer never
// recognized its Sigma2 as acknowledged and retransmitted it after its own
// timeout; that retransmitted Sigma2 then arrived while this client was
// waiting for Sigma3's actual response (SigmaFinished), on the same
// exchange ID, and was misread as if it were that response
// ("case: expected StatusReport, got opcode 0x31").
func buildCASEMessage(opcode message.Opcode, flags message.ExchangeFlag, exchangeID message.ExchangeID, sourceNodeID message.NodeID, payload []byte, hasAck bool, ackMessageCounter message.MessageCounter) (message.Message, error) {
	protocolHeaderOpts := []message.ProtocolHeaderOption{
		message.WithHeaderExchangeFlags(flags),
		message.WithHeaderOpcode(opcode),
		message.WithHeaderExchangeID(exchangeID),
		message.WithHeaderProtocolID(message.SecureChannel),
	}
	if hasAck {
		protocolHeaderOpts = append(protocolHeaderOpts, message.WithHeaderAckCounter(ackMessageCounter))
	}
	msg := message.NewMessage(
		message.WithMessageFrameHeader(message.NewHeader(
			message.WithHeaderSessionID(0),
			message.WithHeaderSecurityFlags(0x00),
			message.WithHeaderMessageCounter(message.NewMessageCounter()),
			message.WithHeaderSourceNodeID(sourceNodeID),
		)),
		message.WithMessageProtocolHeader(message.NewProtocolHeader(protocolHeaderOpts...)),
		message.WithMessagePayload(payload),
	)
	return msg, nil
}

// transmitAndReceiveWithRetry sends payload and waits for a reply on
// exchangeID, retrying the send if a full attempt window (caseRetryInterval,
// bounded by ctx's own deadline if sooner) elapses with no response — see
// caseRetryAttempts' doc comment for why this is needed at all. Only
// timeouts are retried; any other error (a malformed reply, the transport
// itself failing) is returned immediately.
func transmitAndReceiveWithRetry(ctx context.Context, t Transport, exchangeID message.ExchangeID, payload []byte) ([]byte, error) {
	var lastErr error
	for range caseRetryAttempts {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, caseRetryInterval)
		err := t.Transmit(attemptCtx, payload)
		if err != nil {
			cancel()
			return nil, err
		}
		raw, err := receiveSkipAck(attemptCtx, t, exchangeID)
		cancel()
		if err == nil {
			return raw, nil
		}
		if !isTimeoutError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// receiveSkipAck reads messages from t until it finds one on exchangeID that
// isn't a standalone MRP ack, discarding everything else along the way.
//
// The discarding is not optional: this transport may now be the same
// connection PASE/commissioning already used (see
// matter/operational_transport.go's resolveOperationalTransport), rather
// than a dedicated one opened fresh just for this CASE exchange. Without
// checking exchangeID, a stray, late, or duplicate packet left over from an
// earlier exchange on that shared connection — this codebase observed a
// stale SecureChannel StatusReport{SUCCESS} being misread as "the response
// to Sigma1" — would be handed back to the caller as if it were the actual
// reply.
func receiveSkipAck(ctx context.Context, t Transport, exchangeID message.ExchangeID) ([]byte, error) {
	for {
		b, err := t.Receive(ctx)
		if err != nil {
			return nil, err
		}
		msg, err := message.NewMessageFromBytes(b)
		if err != nil {
			return nil, fmt.Errorf("case: parse received message: %w", err)
		}
		if msg.Opcode().IsMRPStandaloneAck() {
			continue
		}
		if msg.ExchangeID() != exchangeID {
			log.Debugf("case: received message for a different exchange (got %v, want %v), waiting for next message", msg.ExchangeID(), exchangeID)
			continue
		}
		return b, nil
	}
}

func verifyCertificateChain(leafDER, icacDER []byte, root *x509.Certificate) error {
	leaf, err := parseCertificateBytes(leafDER)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	intermediates := x509.NewCertPool()
	if len(icacDER) != 0 {
		icac, err := parseCertificateBytes(icacDER)
		if err != nil {
			return err
		}
		intermediates.AddCert(icac)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	})
	return err
}

// PeerMRPParameters returns the MRP parameters the responder announced in
// its Sigma2, defaults for those it did not, for the session's
// retransmissions (session.WithPeerMRPParameters). They are known once
// EstablishSession returns.
func (i *Initiator) PeerMRPParameters() session.MRPParameters {
	return i.peerMRP
}

// verifyResponderIdentity checks that the responder's NOC names the node the
// Sigma1 destination identifier targeted, on the initiator's fabric. The
// chain verification only proves that the NOC was issued on the fabric:
// without this check, any node of the fabric could answer for another
// (4.14.2. Certificate Authenticated Session Establishment).
func verifyResponderIdentity(noc *x509.Certificate, peerNodeID, fabricID uint64) error {
	nodeID, nocFabricID, err := credentials.CertificateIdentity(noc)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnexpectedResponder, err)
	}
	if nodeID != peerNodeID {
		return fmt.Errorf("%w: the NOC names node 0x%016X, not 0x%016X", ErrUnexpectedResponder, nodeID, peerNodeID)
	}
	if nocFabricID != fabricID {
		return fmt.Errorf("%w: the NOC names fabric 0x%016X, not 0x%016X", ErrUnexpectedResponder, nocFabricID, fabricID)
	}
	return nil
}
