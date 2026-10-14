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

package caseprotocol

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sync"

	mcrypto "github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// Session resumption (Matter Core 4.14.2.2): a node which shared a CASE
// session with a peer keeps the session's shared secret under a resumption
// ID, and the next CASE between them proves knowledge of that secret with a
// MIC instead of certificates and signatures. The constants and the key
// schedule follow connectedhomeip's CASESession.
var (
	sigma1ResumeInfo         = []byte("Sigma1_Resume")
	sigma2ResumeInfo         = []byte("Sigma2_Resume")
	sigma1ResumeNonce        = []byte("NCASE_SigmaS1")
	sigma2ResumeNonce        = []byte("NCASE_SigmaS2")
	sessionResumptionKeyInfo = []byte("SessionResumptionKeys")
)

// Sigma1 resumption field tags (4.14.2.3).
const (
	tagSigma1ResumptionID = 6
	tagSigma1ResumeMIC    = 7
)

// Sigma2_Resume field tags (4.14.2.2.2).
const (
	tagSigma2ResumeResumptionID       = 1
	tagSigma2ResumeMIC                = 2
	tagSigma2ResumeResponderSessionID = 3
	tagSigma2ResumeSessionParams      = 4
)

// resumeMICLen is the length of a resume MIC, an AES-CCM tag.
const resumeMICLen = 16

// ErrResumptionMIC is returned when a resume MIC does not verify.
var ErrResumptionMIC = errors.New("case: resume MIC does not verify")

// ResumptionState is what an initiator keeps of a CASE session with a peer
// to resume the next one: its resumption ID and shared secret. It is as
// sensitive as session keys.
type ResumptionState struct {
	ResumptionID []byte
	SharedSecret []byte
}

func (s *ResumptionState) valid() bool {
	return s != nil && len(s.ResumptionID) == resumptionIDLen && len(s.SharedSecret) != 0
}

func (s *ResumptionState) clone() *ResumptionState {
	if s == nil {
		return nil
	}
	return &ResumptionState{ResumptionID: cloneBytes(s.ResumptionID), SharedSecret: cloneBytes(s.SharedSecret)}
}

// resumeMIC computes a resume MIC: the AES-CCM tag over nothing, keyed with
// HKDF(sharedSecret, initiatorRandom || resumptionID, info).
func resumeMIC(sharedSecret, initiatorRandom, resumptionID, info, nonce []byte) ([]byte, error) {
	salt := append(cloneBytes(initiatorRandom), resumptionID...)
	key, err := mcrypto.CryptoKDF(sharedSecret, salt, info, cryptoSymmetricKeyLen)
	if err != nil {
		return nil, fmt.Errorf("case: derive resume key: %w", err)
	}
	mic, err := mcrypto.CryptoCCMEncrypt(key, nonce, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("case: compute resume MIC: %w", err)
	}
	if len(mic) != resumeMICLen {
		return nil, fmt.Errorf("case: resume MIC is %d bytes", len(mic))
	}
	return mic, nil
}

func verifyResumeMIC(mic, sharedSecret, initiatorRandom, resumptionID, info, nonce []byte) error {
	want, err := resumeMIC(sharedSecret, initiatorRandom, resumptionID, info, nonce)
	if err != nil {
		return err
	}
	if len(mic) != resumeMICLen || !bytesEqualConstantTime(mic, want) {
		return ErrResumptionMIC
	}
	return nil
}

func bytesEqualConstantTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// deriveResumedSessionKeys derives the keys of a resumed session from the
// shared secret, salted with the initiator random and the resumption ID
// the Sigma1 named (connectedhomeip's kFinishedViaResume).
func deriveResumedSessionKeys(sharedSecret, initiatorRandom, resumptionID []byte, initiatorSID, responderSID session.SessionID, localNodeID, peerNodeID session.NodeID) (session.SessionKeys, error) {
	salt := append(cloneBytes(initiatorRandom), resumptionID...)
	derived, err := mcrypto.CryptoKDF(sharedSecret, salt, sessionResumptionKeyInfo, 3*cryptoSymmetricKeyLen)
	if err != nil {
		return nil, fmt.Errorf("case: derive resumed session keys: %w", err)
	}
	return newSessionKeys(
		derived[0:cryptoSymmetricKeyLen],
		derived[cryptoSymmetricKeyLen:2*cryptoSymmetricKeyLen],
		derived[2*cryptoSymmetricKeyLen:3*cryptoSymmetricKeyLen],
		initiatorSID, responderSID, localNodeID, peerNodeID,
	), nil
}

func newResumptionID() ([]byte, error) {
	id := make([]byte, resumptionIDLen)
	if _, err := rand.Read(id); err != nil {
		return nil, fmt.Errorf("case: resumption ID: %w", err)
	}
	return id, nil
}

// sigma2Resume is a Sigma2_Resume message (4.14.2.2.2).
type sigma2Resume struct {
	ResumptionID       []byte
	MIC                []byte
	ResponderSessionID uint16
	SessionParams      sessionParams
	// ResponderMRP are the MRP parameters of the responder's
	// session-parameter-struct, defaults for those it leaves out; decoded
	// only.
	ResponderMRP session.MRPParameters
}

func encodeSigma2Resume(v sigma2Resume) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(tagSigma2ResumeResumptionID), v.ResumptionID); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(tagSigma2ResumeMIC), v.MIC); err != nil {
		return nil, err
	}
	enc.PutUnsigned2(tlv.NewContextTag(tagSigma2ResumeResponderSessionID), v.ResponderSessionID)
	encodeSessionParams(enc, tlv.NewContextTag(tagSigma2ResumeSessionParams), v.SessionParams)
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return cloneBytes(enc.Bytes()), nil
}

func decodeSigma2Resume(b []byte) (sigma2Resume, error) {
	octets, uints, err := topLevelFields(b, "Sigma2_Resume")
	if err != nil {
		return sigma2Resume{}, err
	}
	out := sigma2Resume{
		ResumptionID:  octets[tagSigma2ResumeResumptionID],
		MIC:           octets[tagSigma2ResumeMIC],
		SessionParams: sessionParams{},
		ResponderMRP:  decodeMRPParameters(b, tagSigma2ResumeSessionParams),
	}
	sessionID, ok := uints[tagSigma2ResumeResponderSessionID]
	switch {
	case len(out.ResumptionID) != resumptionIDLen:
		return sigma2Resume{}, errors.New("case: Sigma2_Resume: missing resumption ID")
	case len(out.MIC) != resumeMICLen:
		return sigma2Resume{}, errors.New("case: Sigma2_Resume: missing resume MIC")
	case !ok || sessionID == 0 || 0xFFFF < sessionID:
		return sigma2Resume{}, errors.New("case: Sigma2_Resume: invalid responder session ID")
	}
	out.ResponderSessionID = uint16(sessionID)
	return out, nil
}

// ResponderResumption is what a responder keeps of a CASE session to
// resume it: the shared secret and who the initiator was, on which fabric.
type ResponderResumption struct {
	ResumptionID []byte
	SharedSecret []byte
	FabricIndex  uint8
	PeerNodeID   uint64
	PeerCATs     []uint32
}

// ResponderResumptionStore keeps the sessions a responder can resume
// (connectedhomeip's SessionResumptionStorage).
type ResponderResumptionStore interface {
	// Find returns the resumption with the ID.
	Find(resumptionID []byte) (ResponderResumption, bool)
	// Save keeps a resumption, replacing the one of the same initiator on
	// the same fabric.
	Save(r ResponderResumption)
	// Delete forgets the resumption with the ID.
	Delete(resumptionID []byte)
	// DeleteFabric forgets the resumptions of a fabric, as when it is
	// removed.
	DeleteFabric(fabricIndex uint8)
}

// DefaultResponderResumptions is how many resumptions a store from
// NewResponderResumptionStore keeps; the oldest goes first.
const DefaultResponderResumptions = 16

type responderResumptionStore struct {
	mutex   sync.Mutex
	limit   int
	entries []ResponderResumption
}

// NewResponderResumptionStore returns an in-memory ResponderResumptionStore
// which keeps the latest DefaultResponderResumptions resumptions.
func NewResponderResumptionStore() ResponderResumptionStore {
	return &responderResumptionStore{mutex: sync.Mutex{}, limit: DefaultResponderResumptions, entries: nil}
}

func (s *responderResumptionStore) Find(id []byte) (ResponderResumption, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for _, e := range s.entries {
		if bytes.Equal(e.ResumptionID, id) {
			return cloneResponderResumption(e), true
		}
	}
	return ResponderResumption{}, false
}

func (s *responderResumptionStore) Save(r ResponderResumption) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.entries = slices.DeleteFunc(s.entries, func(e ResponderResumption) bool {
		return e.FabricIndex == r.FabricIndex && e.PeerNodeID == r.PeerNodeID
	})
	s.entries = append(s.entries, cloneResponderResumption(r))
	if len(s.entries) > s.limit {
		s.entries = s.entries[len(s.entries)-s.limit:]
	}
}

func (s *responderResumptionStore) Delete(id []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.entries = slices.DeleteFunc(s.entries, func(e ResponderResumption) bool { return bytes.Equal(e.ResumptionID, id) })
}

func (s *responderResumptionStore) DeleteFabric(fabricIndex uint8) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.entries = slices.DeleteFunc(s.entries, func(e ResponderResumption) bool { return e.FabricIndex == fabricIndex })
}

func cloneResponderResumption(r ResponderResumption) ResponderResumption {
	return ResponderResumption{
		ResumptionID: cloneBytes(r.ResumptionID),
		SharedSecret: cloneBytes(r.SharedSecret),
		FabricIndex:  r.FabricIndex,
		PeerNodeID:   r.PeerNodeID,
		PeerCATs:     slices.Clone(r.PeerCATs),
	}
}
