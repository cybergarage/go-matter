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

package mockdevice

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"fmt"

	"github.com/cybergarage/go-matter/matter/credentials/chipcert"
	mcrypto "github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/io"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

var (
	caseSigma2Nonce = []byte("NCASE_Sigma2N")
	caseSigma3Nonce = []byte("NCASE_Sigma3N")
)

// handleCASE runs this mock device's CASE responder role to completion over
// t against the fabric fs was populated with by AddTrustedRootCertificate/
// AddNOC, and returns a secure session (already role-swapped, see
// swapRoleSessionKeys) once Sigma3 verifies and SigmaFinished is sent.
//
// This device only ever has one fabric/NOC (fs), so Sigma1 matching is a
// single HMAC comparison, not FindLocalNodeFromDestinationId's loop over a
// real fabric table.
func handleCASE(ctx context.Context, t io.Transport, fs *fabricState) (session.SecureSession, error) {
	rootCert, err := x509.ParseCertificate(fs.rootCertDER)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: parse root certificate: %w", err)
	}
	rootPub, ok := rootCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mockdevice: CASE: root public key is not ECDSA")
	}
	rootPublicKeyBytes := elliptic.Marshal(rootPub.Curve, rootPub.X, rootPub.Y)

	compressedFabricIDBytes, err := computeCompressedFabricIDBytes(rootPublicKeyBytes, fs.fabricID)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: compressed fabric ID: %w", err)
	}
	operationalIPK, err := deriveOperationalIPK(fs.rawIPK, compressedFabricIDBytes)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: derive operational IPK: %w", err)
	}

	// 1) Sigma1: receive and match DestinationID. The commissioner's own
	// standalone MRP ack of this device's last PASE-session IM response
	// (e.g. AddNOC's NOCResponse) can still be in flight on the same
	// loopback socket handleCASE now reads raw from — session.SecureSession
	// would normally discard such acks internally (see swapRoleSessionKeys'
	// doc comment), but that filtering only applies once a session exists,
	// so it's done by hand here for this one unsecured, pre-session read.
	sigma1Msg, err := receiveNonAckMessage(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: receive Sigma1: %w", err)
	}
	sigma1, err := decodeSigma1(sigma1Msg.Payload())
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: %w", err)
	}
	candidateDestinationID := computeDestinationID(operationalIPK, sigma1.initiatorRandom, rootPublicKeyBytes, fs.fabricID, fs.nodeID)
	if subtle.ConstantTimeCompare(candidateDestinationID, sigma1.destinationID) != 1 {
		if err := sendCASEStatusReport(ctx, t, sigma1Msg.ExchangeID(), false, 0, 1 /* FAILURE */, 1 /* NO_SHARED_TRUST_ROOTS */); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("mockdevice: CASE: Sigma1 DestinationID mismatch")
	}

	// 2) Sigma2: generate ephemeral key, encrypt TBEData2, send — acking Sigma1.
	responderEphPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: generate ephemeral key: %w", err)
	}
	responderEphPubKey := elliptic.Marshal(elliptic.P256(), responderEphPriv.PublicKey.X, responderEphPriv.PublicKey.Y)
	responderRandom := make([]byte, 32)
	if _, err := rand.Read(responderRandom); err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: generate responderRandom: %w", err)
	}
	responderSessionID := uint16(0xBEEF)

	sharedSecret, err := ecdhSharedSecretX(responderEphPriv.D.FillBytes(make([]byte, 32)), sigma1.initiatorEphPubKey)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: Sigma2 ECDH: %w", err)
	}
	s2k, err := deriveSigma2Key(sharedSecret, operationalIPK, responderRandom, responderEphPubKey, sigma1Msg.Payload())
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: derive S2K: %w", err)
	}

	nocTLV, err := chipcert.DERToTLV(fs.nocDER)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: encode own NOC: %w", err)
	}
	var icacTLV []byte
	if len(fs.icacDER) != 0 {
		icacTLV, err = chipcert.DERToTLV(fs.icacDER)
		if err != nil {
			return nil, fmt.Errorf("mockdevice: CASE: encode own ICAC: %w", err)
		}
	}
	sigma2TBS, err := encodeSigmaTBSData(nocTLV, icacTLV, responderEphPubKey, sigma1.initiatorEphPubKey)
	if err != nil {
		return nil, err
	}
	sigma2Sig, err := signRaw(fs.nocKey, sigma2TBS)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: sign Sigma2: %w", err)
	}
	resumptionID := make([]byte, 16)
	if _, err := rand.Read(resumptionID); err != nil {
		return nil, err
	}
	tbeData2, err := encodeSigma2TBEData(nocTLV, icacTLV, sigma2Sig, resumptionID)
	if err != nil {
		return nil, err
	}
	encrypted2, err := mcrypto.CryptoCCMEncrypt(s2k, caseSigma2Nonce, tbeData2, nil)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: encrypt Sigma2: %w", err)
	}
	sigma2Payload, err := encodeSigma2(responderRandom, responderSessionID, responderEphPubKey, encrypted2)
	if err != nil {
		return nil, err
	}
	sigma2Msg, err := buildCASEMessage(message.CASESigma2, sigma1Msg.ExchangeID(), sigma2Payload, true, sigma1Msg.MessageCounter())
	if err != nil {
		return nil, err
	}
	sigma2Bytes, err := sigma2Msg.Bytes()
	if err != nil {
		return nil, err
	}
	if err := t.Transmit(ctx, sigma2Bytes); err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: transmit Sigma2: %w", err)
	}

	// 3) Sigma3: receive, decrypt, verify chain + signature — acking Sigma2 already sent above.
	sigma3Raw, err := t.Receive(ctx)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: receive Sigma3: %w", err)
	}
	sigma3Msg, err := message.NewMessageFromBytes(sigma3Raw)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: parse Sigma3 message: %w", err)
	}
	encrypted3, err := decodeSigma3(sigma3Msg.Payload())
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: %w", err)
	}
	s3k, err := deriveSigma3Key(sharedSecret, operationalIPK, sigma1Msg.Payload(), sigma2Msg.Payload())
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: derive S3K: %w", err)
	}
	tbeData3Bytes, err := mcrypto.CryptoCCMDecrypt(s3k, caseSigma3Nonce, encrypted3, nil)
	if err != nil {
		if serr := sendCASEStatusReport(ctx, t, sigma3Msg.ExchangeID(), false, 0, 1, 2 /* INVALID_PARAMETER */); serr != nil {
			return nil, serr
		}
		return nil, fmt.Errorf("mockdevice: CASE: decrypt Sigma3: %w", err)
	}
	tbeData3, err := decodeSigma3TBEData(tbeData3Bytes)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: %w", err)
	}

	initiatorNOCDER, err := chipcert.TLVToDER(tbeData3.initiatorNOCTLV)
	if err != nil {
		if serr := sendCASEStatusReport(ctx, t, sigma3Msg.ExchangeID(), false, 0, 1, 2); serr != nil {
			return nil, serr
		}
		return nil, fmt.Errorf("mockdevice: CASE: decode initiator NOC: %w", err)
	}
	var initiatorICACDER []byte
	if len(tbeData3.initiatorICACTLV) != 0 {
		initiatorICACDER, err = chipcert.TLVToDER(tbeData3.initiatorICACTLV)
		if err != nil {
			return nil, fmt.Errorf("mockdevice: CASE: decode initiator ICAC: %w", err)
		}
	}
	initiatorLeaf, err := x509.ParseCertificate(initiatorNOCDER)
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: parse initiator NOC: %w", err)
	}
	// Chain validation using Go's default KeyUsages (ExtKeyUsageServerAuth):
	// this is what independently reproduces connectedhomeip's CASESession
	// requirement (mValidContext.mRequiredKeyPurposes = kServerAuth) that
	// ANY NOC validated during CASE — initiator's or responder's — carry
	// the ServerAuth key purpose, which a real device enforced but this
	// project's admin NOC template didn't originally satisfy.
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	intermediates := x509.NewCertPool()
	if len(initiatorICACDER) != 0 {
		icac, err := x509.ParseCertificate(initiatorICACDER)
		if err != nil {
			return nil, fmt.Errorf("mockdevice: CASE: parse initiator ICAC: %w", err)
		}
		intermediates.AddCert(icac)
	}
	if _, err := initiatorLeaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates}); err != nil {
		if serr := sendCASEStatusReport(ctx, t, sigma3Msg.ExchangeID(), false, 0, 1, 2); serr != nil {
			return nil, serr
		}
		return nil, fmt.Errorf("mockdevice: CASE: verify initiator certificate chain: %w", err)
	}
	sigma3TBS, err := encodeSigmaTBSData(tbeData3.initiatorNOCTLV, tbeData3.initiatorICACTLV, sigma1.initiatorEphPubKey, responderEphPubKey)
	if err != nil {
		return nil, err
	}
	initiatorPub, ok := initiatorLeaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mockdevice: CASE: initiator public key is not ECDSA")
	}
	if !verifyRaw(initiatorPub, sigma3TBS, tbeData3.signature) {
		if serr := sendCASEStatusReport(ctx, t, sigma3Msg.ExchangeID(), false, 0, 1, 2); serr != nil {
			return nil, serr
		}
		return nil, fmt.Errorf("mockdevice: CASE: Sigma3 signature verification failed")
	}

	// 4) SigmaFinished: derive final session keys, ack Sigma3, send success.
	i2rKey, r2iKey, err := deriveCASESessionKeys(sharedSecret, operationalIPK, sigma1Msg.Payload(), sigma2Msg.Payload(), sigma3Msg.Payload())
	if err != nil {
		return nil, fmt.Errorf("mockdevice: CASE: derive session keys: %w", err)
	}
	if err := sendCASEStatusReport(ctx, t, sigma3Msg.ExchangeID(), true, sigma3Msg.MessageCounter(), 0, 0); err != nil {
		return nil, err
	}

	// natural represents the session keys in the commissioner's (initiator's)
	// frame of reference — LocalNodeID is the *initiator's* own node ID
	// (the admin, fs.caseAdminSubject) and PeerNodeID is the device's
	// (fs.nodeID) — mirroring matter/protocol/case/client.go's own
	// deriveSessionKeys(..., session.NodeID(inputs.nodeID) /* admin, local */,
	// session.NodeID(i.peerNodeID) /* device, peer */). swapRoleSessionKeys
	// below then inverts both into this device's own frame of reference.
	// Getting this backwards here (device's own node ID as "local" in the
	// pre-swap struct) doesn't break the handshake itself — Sigma1/2/3 and
	// SigmaFinished all completed — since node IDs never enter their KDF
	// salts, only the CCM nonce of application traffic *after* the
	// handshake, which is exactly where this was first caught: the key
	// bytes matched byte-for-byte on both sides, but decrypting a real
	// post-handshake message still failed, because the nonce's node-ID
	// component was swapped an extra, wrong time.
	natural := simpleSessionKeys{
		i2rKey:               i2rKey,
		r2iKey:               r2iKey,
		attestationChallenge: nil,
		initiatorSessionID:   session.SessionID(sigma1.initiatorSessionID),
		responderSessionID:   session.SessionID(responderSessionID),
		localNodeID:          session.NodeID(fs.caseAdminSubject),
		peerNodeID:           session.NodeID(fs.nodeID),
	}
	return session.NewSecureSession(t, swapRoleSessionKeys(natural)), nil
}

// receiveNonAckMessage reads raw messages from t, discarding both encrypted
// datagrams (session ID != 0 — leftover traffic on the still-secure PASE
// session, such as the commissioner's own standalone ack of this device's
// last PASE-phase IM response, which NewMessageFromBytes can't parse as a
// plaintext protocol header/payload) and unsecured standalone MRP acks,
// until an actual unsecured, substantive message (Sigma1) arrives.
func receiveNonAckMessage(ctx context.Context, t io.Transport) (message.Message, error) {
	for {
		raw, err := t.Receive(ctx)
		if err != nil {
			return nil, err
		}
		header, err := message.NewHeaderFromBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("parse frame header: %w", err)
		}
		if header.SessionID() != 0 {
			continue
		}
		msg, err := message.NewMessageFromBytes(raw)
		if err != nil {
			return nil, fmt.Errorf("parse message: %w", err)
		}
		if msg.Opcode().IsMRPStandaloneAck() {
			continue
		}
		return msg, nil
	}
}

// buildCASEMessage builds an unsecured (SessionID 0) SecureChannel message
// for CASE, mirroring matter/protocol/case/client.go's own buildCASEMessage
// (unexported, hence reimplemented here) including its ack-counter
// handling: hasAck/ackMessageCounter set message.WithHeaderAckCounter, not
// a bare AckFlag with no counter behind it — the exact bug class (Sigma3's
// ack of Sigma2 silently claiming to ack message counter 0) this whole
// project's CASE work hit against a real device.
func buildCASEMessage(opcode message.Opcode, exchangeID message.ExchangeID, payload []byte, hasAck bool, ackMessageCounter message.MessageCounter) (message.Message, error) {
	protocolHeaderOpts := []message.ProtocolHeaderOption{
		message.WithHeaderExchangeFlags(message.ReliabilityFlag),
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
		)),
		message.WithMessageProtocolHeader(message.NewProtocolHeader(protocolHeaderOpts...)),
		message.WithMessagePayload(payload),
	)
	return msg, nil
}

// sendCASEStatusReport sends a fixed-width, little-endian StatusReport
// (SigmaFinished on success, or a failure report) — not TLV, matching
// connectedhomeip's StatusReport::Parse and this repo's own
// matter/protocol/case's parseStatusReport.
func sendCASEStatusReport(ctx context.Context, t io.Transport, exchangeID message.ExchangeID, hasAck bool, ackMessageCounter message.MessageCounter, generalCode, protocolCode uint16) error {
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:2], generalCode)
	binary.LittleEndian.PutUint32(payload[2:6], uint32(message.SecureChannel))
	binary.LittleEndian.PutUint16(payload[6:8], protocolCode)

	msg, err := buildCASEMessage(message.StatusReport, exchangeID, payload, hasAck, ackMessageCounter)
	if err != nil {
		return err
	}
	wire, err := msg.Bytes()
	if err != nil {
		return err
	}
	return t.Transmit(ctx, wire)
}
