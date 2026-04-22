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

// Package caseprotocol provides CASE (Certificate Authenticated Session Establishment)
// client primitives used to finalize commissioning over the operational network.
package caseprotocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/config"
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
)

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

// Initiator represents a CASE client.
type Initiator struct {
	t          Transport
	cfg        config.AdministratorConfig
	peerNodeID uint64
	ipk        []byte
}

// NewInitiator creates a new CASE initiator.
func NewInitiator(t Transport, cfg config.AdministratorConfig, opts ...Option) *Initiator {
	i := &Initiator{
		t:   t,
		cfg: cfg,
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
	destinationID := computeDestinationID(i.ipk, initiatorRandom, inputs.rootPublicKey, inputs.fabricID, i.peerNodeID)
	log.Infof(
		"CASE target: peer_node_id=0x%016X destination_id=%s initiator_eph=%s",
		i.peerNodeID,
		redactedBytes(destinationID),
		redactedBytes(initiatorEphPubKey),
	)

	exchangeID := message.NewFirstExchangeID()
	sigma1Payload, err := encodeSigma1(sigma1{
		InitiatorRandom:    initiatorRandom,
		InitiatorSessionID: uint16(initiatorSessionID),
		DestinationID:      destinationID,
		InitiatorEphPubKey: initiatorEphPubKey,
	})
	if err != nil {
		return nil, err
	}
	sigma1Msg, err := buildCASEMessage(message.CASESigma1, message.InitiatorFlag|message.ReliabilityFlag, exchangeID, sigma1Payload)
	if err != nil {
		return nil, err
	}
	sigma1Bytes, err := sigma1Msg.Bytes()
	if err != nil {
		return nil, err
	}
	log.Infof("CASE Sigma1: session_id=0x%04X exchange_id=0x%04X payload=%s", initiatorSessionID, exchangeID, redactedBytes(sigma1Payload))
	log.HexDebug(sigma1Bytes)
	if err := i.t.Transmit(ctx, sigma1Bytes); err != nil {
		return nil, fmt.Errorf("case: transmit Sigma1: %w", err)
	}

	sigma2Raw, err := receiveSkipAck(ctx, i.t)
	if err != nil {
		return nil, fmt.Errorf("case: receive Sigma2: %w", err)
	}
	sigma2Msg, err := message.NewMessageFromBytes(sigma2Raw)
	if err != nil {
		return nil, fmt.Errorf("case: parse Sigma2 message: %w", err)
	}
	if !sigma2Msg.Opcode().IsCASESigma2() {
		return nil, fmt.Errorf("case: expected Sigma2, got opcode 0x%02x", uint8(sigma2Msg.Opcode()))
	}
	sigma2, err := decodeSigma2(sigma2Msg.Payload())
	if err != nil {
		log.Infof("CASE Sigma2: malformed payload")
		return nil, err
	}
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
	s2k, err := deriveSigma2Key(sharedSecret, i.ipk, sigma2.ResponderRandom, sigma2.ResponderEphPubKey, sigma1Msg.Payload())
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
	sigma2TBS, err := encodeSigmaTBSData(tbeData2.ResponderNOC, tbeData2.ResponderICAC, sigma2.ResponderEphPubKey, initiatorEphPubKey)
	if err != nil {
		return nil, err
	}
	if !verifySignatureFromCert(responderLeaf, sigma2TBS, tbeData2.Signature) {
		log.Infof("CASE Sigma2: signature verification failed")
		return nil, fmt.Errorf("case: responder Sigma2 signature verification failed")
	}
	log.Infof("CASE Sigma2: signature verification ok")

	sigma3TBS, err := encodeSigmaTBSData(inputs.nocDER, inputs.icacDER, initiatorEphPubKey, sigma2.ResponderEphPubKey)
	if err != nil {
		return nil, err
	}
	sigma3Sig, err := signWithKey(inputs.privateKey, sigma3TBS)
	if err != nil {
		return nil, fmt.Errorf("case: Sigma3 signature: %w", err)
	}
	sigma3TBEData, err := encodeSigma3TBEData(sigma3TBEData{
		InitiatorNOC:  inputs.nocDER,
		InitiatorICAC: inputs.icacDER,
		Signature:     sigma3Sig,
	})
	if err != nil {
		return nil, err
	}
	s3k, err := deriveSigma3Key(sharedSecret, i.ipk, sigma1Msg.Payload(), sigma2Msg.Payload())
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
	sigma3Msg, err := buildCASEMessage(message.CASESigma3, message.InitiatorFlag|message.ReliabilityFlag|message.AckFlag, exchangeID, sigma3Payload)
	if err != nil {
		return nil, err
	}
	sigma3Bytes, err := sigma3Msg.Bytes()
	if err != nil {
		return nil, err
	}
	log.Infof("CASE Sigma3: encrypted3=%s", redactedBytes(encrypted3))
	log.HexDebug(sigma3Bytes)
	if err := i.t.Transmit(ctx, sigma3Bytes); err != nil {
		return nil, fmt.Errorf("case: transmit Sigma3: %w", err)
	}

	statusRaw, err := receiveSkipAck(ctx, i.t)
	if err != nil {
		return nil, fmt.Errorf("case: receive SigmaFinished: %w", err)
	}
	if err := parseStatusReport(statusRaw); err != nil {
		log.Infof("CASE SigmaFinished: status failure")
		return nil, err
	}
	log.Infof("CASE SigmaFinished: success")

	sessionKeys, err := deriveSessionKeys(sharedSecret, i.ipk, sigma1RawPayload(sigma1Msg), sigma2RawPayload(sigma2Msg), sigma3RawPayload(sigma3Msg), initiatorSessionID, session.SessionID(sigma2.ResponderSessionID), session.NodeID(inputs.nodeID))
	if err != nil {
		return nil, err
	}
	return sessionKeys, nil
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

func buildCASEMessage(opcode message.Opcode, flags message.ExchangeFlag, exchangeID message.ExchangeID, payload []byte) (message.Message, error) {
	msg := message.NewMessage(
		message.WithMessageFrameHeader(message.NewHeader(
			message.WithHeaderSessionID(0),
			message.WithHeaderSecurityFlags(0x00),
			message.WithHeaderMessageCounter(message.NewMessageCounter()),
		)),
		message.WithMessageProtocolHeader(message.NewProtocolHeader(
			message.WithHeaderExchangeFlags(flags),
			message.WithHeaderOpcode(opcode),
			message.WithHeaderExchangeID(exchangeID),
			message.WithHeaderProtocolID(message.SecureChannel),
		)),
		message.WithMessagePayload(payload),
	)
	return msg, nil
}

func receiveSkipAck(ctx context.Context, t Transport) ([]byte, error) {
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
