package caseprotocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

type sigma1 struct {
	InitiatorRandom    []byte
	InitiatorSessionID uint16
	DestinationID      []byte
	InitiatorEphPubKey []byte
}

type sigma2 struct {
	ResponderRandom    []byte
	ResponderSessionID uint16
	ResponderEphPubKey []byte
	Encrypted2         []byte
}

type sigma3 struct {
	Encrypted3 []byte
}

type sigma2TBEData struct {
	ResponderNOC  []byte
	ResponderICAC []byte
	Signature     []byte
	ResumptionID  []byte
}

type sigma3TBEData struct {
	InitiatorNOC  []byte
	InitiatorICAC []byte
	Signature     []byte
}

func newSessionID() (session.SessionID, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	v := binary.LittleEndian.Uint16(b[:])
	if v == 0 {
		v = 1
	}
	return session.SessionID(v), nil
}

func encodeSigma1(v sigma1) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), v.InitiatorRandom); err != nil {
		return nil, err
	}
	enc.PutUnsigned2(tlv.NewContextTag(2), v.InitiatorSessionID)
	if err := enc.PutOctet(tlv.NewContextTag(3), v.DestinationID); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(4), v.InitiatorEphPubKey); err != nil {
		return nil, err
	}
	enc.EndContainer()
	return cloneBytes(enc.Bytes()), nil
}

func decodeSigma2(b []byte) (sigma2, error) {
	dec := tlv.NewDecoderWithBytes(b)
	if !dec.Next() {
		return sigma2{}, fmt.Errorf("case: Sigma2: empty payload")
	}
	if !dec.Element().Type().IsStructure() {
		return sigma2{}, fmt.Errorf("case: Sigma2: expected structure")
	}
	var out sigma2
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
			out.ResponderRandom, _ = elem.Bytes()
		case 2:
			out.ResponderSessionID, _ = elem.Unsigned2()
		case 3:
			out.ResponderEphPubKey, _ = elem.Bytes()
		case 4:
			out.Encrypted2, _ = elem.Bytes()
		}
	}
	if len(out.ResponderRandom) != randomLen {
		return sigma2{}, fmt.Errorf("case: Sigma2: missing responder random")
	}
	if out.ResponderSessionID == 0 {
		return sigma2{}, fmt.Errorf("case: Sigma2: missing responder session ID")
	}
	if len(out.ResponderEphPubKey) == 0 {
		return sigma2{}, fmt.Errorf("case: Sigma2: missing responder ephemeral public key")
	}
	if len(out.Encrypted2) == 0 {
		return sigma2{}, fmt.Errorf("case: Sigma2: missing encrypted2")
	}
	return out, nil
}

func encodeSigma3(v sigma3) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), v.Encrypted3); err != nil {
		return nil, err
	}
	enc.EndContainer()
	return cloneBytes(enc.Bytes()), nil
}

func decodeSigma2TBEData(b []byte) (sigma2TBEData, error) {
	dec := tlv.NewDecoderWithBytes(b)
	if !dec.Next() {
		return sigma2TBEData{}, fmt.Errorf("case: Sigma2 encrypted payload is empty")
	}
	if !dec.Element().Type().IsStructure() {
		return sigma2TBEData{}, fmt.Errorf("case: Sigma2 encrypted payload expected structure")
	}
	var out sigma2TBEData
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
			out.ResponderNOC, _ = elem.Bytes()
		case 2:
			out.ResponderICAC, _ = elem.Bytes()
		case 3:
			out.Signature, _ = elem.Bytes()
		case 4:
			out.ResumptionID, _ = elem.Bytes()
		}
	}
	if len(out.ResponderNOC) == 0 {
		return sigma2TBEData{}, fmt.Errorf("case: Sigma2 encrypted payload missing responder NOC")
	}
	if len(out.Signature) == 0 {
		return sigma2TBEData{}, fmt.Errorf("case: Sigma2 encrypted payload missing signature")
	}
	if len(out.ResumptionID) != resumptionIDLen {
		return sigma2TBEData{}, fmt.Errorf("case: Sigma2 encrypted payload missing resumption ID")
	}
	return out, nil
}

func encodeSigma3TBEData(v sigma3TBEData) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), v.InitiatorNOC); err != nil {
		return nil, err
	}
	if len(v.InitiatorICAC) != 0 {
		if err := enc.PutOctet(tlv.NewContextTag(2), v.InitiatorICAC); err != nil {
			return nil, err
		}
	}
	if err := enc.PutOctet(tlv.NewContextTag(3), v.Signature); err != nil {
		return nil, err
	}
	enc.EndContainer()
	return cloneBytes(enc.Bytes()), nil
}

func encodeSigmaTBSData(noc, icac, senderEphPubKey, receiverEphPubKey []byte) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), noc); err != nil {
		return nil, err
	}
	if len(icac) != 0 {
		if err := enc.PutOctet(tlv.NewContextTag(2), icac); err != nil {
			return nil, err
		}
	}
	if err := enc.PutOctet(tlv.NewContextTag(3), senderEphPubKey); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(4), receiverEphPubKey); err != nil {
		return nil, err
	}
	enc.EndContainer()
	return cloneBytes(enc.Bytes()), nil
}
