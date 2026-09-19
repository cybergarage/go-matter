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
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// decodedSigma1 holds Sigma1's fields this server needs. Session-parameter
// negotiation (tag 5) is intentionally not decoded — it's optional per spec
// and this server always uses its own fixed defaults for its own outgoing
// messages, matching how a real device's own responder behaves once it
// decides to reply at all.
type decodedSigma1 struct {
	initiatorRandom    []byte
	initiatorSessionID uint16
	destinationID      []byte
	initiatorEphPubKey []byte
}

// decodeSigma1 decodes Sigma1's TLV payload (spec 4.14.2.2 /
// connectedhomeip's Sigma1Tags: initiatorRandom=1, initiatorSessionId=2,
// destinationId=3, initiatorEphPubKey=4, initiatorSessionParams=5
// optional). Depth-tracked so the nested InitiatorSessionParams structure's
// own same-numbered context tags are never mistaken for Sigma1's own
// top-level fields — the exact bug this project's own verification tooling
// hit earlier when session parameters were added to Sigma1 without
// depth-aware decoding.
func decodeSigma1(payload []byte) (decodedSigma1, error) {
	dec := tlv.NewDecoderWithBytes(payload)
	var out decodedSigma1
	depth := 0
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			depth--
			continue
		}
		if ct, ok := elem.Tag().(tlv.ContextTag); ok && depth == 1 {
			switch ct.ContextNumber() {
			case 1:
				out.initiatorRandom, _ = elem.Bytes()
			case 2:
				out.initiatorSessionID, _ = elem.Unsigned2()
			case 3:
				out.destinationID, _ = elem.Bytes()
			case 4:
				out.initiatorEphPubKey, _ = elem.Bytes()
			}
		}
		if elem.Type().IsContainer() {
			depth++
		}
	}
	if err := dec.Error(); err != nil {
		return decodedSigma1{}, err
	}
	if len(out.initiatorRandom) != 32 {
		return decodedSigma1{}, fmt.Errorf("mockdevice: Sigma1: missing or invalid initiatorRandom")
	}
	if len(out.destinationID) != 32 {
		return decodedSigma1{}, fmt.Errorf("mockdevice: Sigma1: missing or invalid destinationId")
	}
	if len(out.initiatorEphPubKey) == 0 {
		return decodedSigma1{}, fmt.Errorf("mockdevice: Sigma1: missing initiatorEphPubKey")
	}
	return out, nil
}

// encodeSigma2 encodes Sigma2's TLV payload: responderRandom(1),
// responderSessionId(2), responderEphPubKey(3), encrypted2(4).
func encodeSigma2(responderRandom []byte, responderSessionID uint16, responderEphPubKey, encrypted2 []byte) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), responderRandom); err != nil {
		return nil, err
	}
	enc.PutUnsigned2(tlv.NewContextTag(2), responderSessionID)
	if err := enc.PutOctet(tlv.NewContextTag(3), responderEphPubKey); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(4), encrypted2); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// encodeSigma2TBEData encodes Sigma2's encrypted payload:
// responderNOC(1, Matter-TLV), responderICAC(2, optional, Matter-TLV),
// signature(3, raw 64 bytes), resumptionID(4, 16 bytes).
func encodeSigma2TBEData(responderNOCTLV, responderICACTLV, signature, resumptionID []byte) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), responderNOCTLV); err != nil {
		return nil, err
	}
	if len(responderICACTLV) != 0 {
		if err := enc.PutOctet(tlv.NewContextTag(2), responderICACTLV); err != nil {
			return nil, err
		}
	}
	if err := enc.PutOctet(tlv.NewContextTag(3), signature); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(4), resumptionID); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// decodedSigma3TBEData holds Sigma3's decrypted fields.
type decodedSigma3TBEData struct {
	initiatorNOCTLV  []byte
	initiatorICACTLV []byte
	signature        []byte
}

// decodeSigma3TBEData decodes Sigma3's decrypted payload:
// initiatorNOC(1), initiatorICAC(2, optional), signature(3).
func decodeSigma3TBEData(b []byte) (decodedSigma3TBEData, error) {
	dec := tlv.NewDecoderWithBytes(b)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		return decodedSigma3TBEData{}, fmt.Errorf("mockdevice: Sigma3 TBEData: expected top-level Structure")
	}
	var out decodedSigma3TBEData
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
		case 1:
			out.initiatorNOCTLV, _ = elem.Bytes()
		case 2:
			out.initiatorICACTLV, _ = elem.Bytes()
		case 3:
			out.signature, _ = elem.Bytes()
		}
	}
	if err := dec.Error(); err != nil {
		return decodedSigma3TBEData{}, err
	}
	if len(out.initiatorNOCTLV) == 0 {
		return decodedSigma3TBEData{}, fmt.Errorf("mockdevice: Sigma3 TBEData: missing initiatorNOC")
	}
	if len(out.signature) == 0 {
		return decodedSigma3TBEData{}, fmt.Errorf("mockdevice: Sigma3 TBEData: missing signature")
	}
	return out, nil
}

// decodeSigma3 decodes Sigma3's outer TLV payload: encrypted3(1).
func decodeSigma3(payload []byte) ([]byte, error) {
	dec := tlv.NewDecoderWithBytes(payload)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		return nil, fmt.Errorf("mockdevice: Sigma3: expected top-level Structure")
	}
	var encrypted3 []byte
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			break
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if ok && ct.ContextNumber() == 1 {
			encrypted3, _ = elem.Bytes()
		}
	}
	if err := dec.Error(); err != nil {
		return nil, err
	}
	if len(encrypted3) == 0 {
		return nil, fmt.Errorf("mockdevice: Sigma3: missing encrypted3")
	}
	return encrypted3, nil
}

// encodeSigmaTBSData encodes the TBS (to-be-signed/to-be-verified)
// structure shared by Sigma2 and Sigma3: senderNOC(1, Matter-TLV),
// senderICAC(2, optional), senderEphPubKey(3), receiverEphPubKey(4).
func encodeSigmaTBSData(nocTLV, icacTLV, senderEphPubKey, receiverEphPubKey []byte) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), nocTLV); err != nil {
		return nil, err
	}
	if len(icacTLV) != 0 {
		if err := enc.PutOctet(tlv.NewContextTag(2), icacTLV); err != nil {
			return nil, err
		}
	}
	if err := enc.PutOctet(tlv.NewContextTag(3), senderEphPubKey); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(4), receiverEphPubKey); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}
