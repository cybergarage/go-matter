package caseprotocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

type sigma1 struct {
	InitiatorRandom    []byte
	InitiatorSessionID uint16
	DestinationID      []byte
	InitiatorEphPubKey []byte
	// InitiatorMRP are the MRP parameters of the initiator's
	// session-parameter-struct, defaults for those it leaves out. They are
	// decoded only; encodeSigma1 sends defaultSessionParams.
	InitiatorMRP session.MRPParameters
}

// sessionParams mirrors connectedhomeip's SessionParameters
// (src/messaging/SessionParameters.h), sent as Sigma1Tags::kInitiatorSessionParams
// (tag 5, optional per spec/ParseSigma1 — but a real device only replied to
// Sigma1 once this was present; see encodeSigma1's doc comment).
type sessionParams struct {
	SessionIdleInterval      uint16
	SessionActiveInterval    uint16
	SessionActiveThreshold   uint16
	DataModelRevision        uint8
	InteractionModelRevision uint8
	SpecificationVersion     uint32
	MaxPathsPerInvoke        uint8
}

// defaultSessionParams are the values connectedhomeip's own reference
// controller (chip-tool) sends, captured byte-for-byte via tcpdump from a
// real, successful Sigma1 on the wire — 500/300/4000ms are the Matter Core
// Spec's default MRP intervals, 12 matches this package's own
// interactionModelRevision constant (matter/protocol/im), and 0x01050100
// (17105152) is the packed Matter specification version chip-tool itself
// advertised.
var defaultSessionParams = sessionParams{
	SessionIdleInterval:      500,
	SessionActiveInterval:    300,
	SessionActiveThreshold:   4000,
	DataModelRevision:        19,
	InteractionModelRevision: 12,
	SpecificationVersion:     0x01050100,
	MaxPathsPerInvoke:        1,
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
	encodeSessionParams(enc, tlv.NewContextTag(5), defaultSessionParams)
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return cloneBytes(enc.Bytes()), nil
}

func encodeSessionParams(enc tlv.Encoder, tag tlv.Tag, p sessionParams) {
	enc.BeginStructure(tag)
	enc.PutUnsigned2(tlv.NewContextTag(1), p.SessionIdleInterval)
	enc.PutUnsigned2(tlv.NewContextTag(2), p.SessionActiveInterval)
	enc.PutUnsigned2(tlv.NewContextTag(3), p.SessionActiveThreshold)
	enc.PutUnsigned1(tlv.NewContextTag(4), p.DataModelRevision)
	enc.PutUnsigned1(tlv.NewContextTag(5), p.InteractionModelRevision)
	enc.PutUnsigned4(tlv.NewContextTag(6), p.SpecificationVersion)
	enc.PutUnsigned1(tlv.NewContextTag(7), p.MaxPathsPerInvoke)
	_ = enc.EndContainer()
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
	depth := 0
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			if depth == 0 {
				break
			}
			depth--
			continue
		}
		// Skip past the contents of nested containers (e.g. the optional
		// ResponderSessionParams structure at tag 5): their own context tag
		// numbers are only meaningful relative to their enclosing
		// container, and reusing this loop's top-level tag switch on them
		// would silently overwrite already-decoded fields that happen to
		// share the same tag number one level up.
		if depth > 0 {
			if elem.Type().IsContainer() {
				depth++
			}
			continue
		}
		if elem.Type().IsContainer() {
			depth++
			continue
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
	depth := 0
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			if depth == 0 {
				break
			}
			depth--
			continue
		}
		// See the matching comment in decodeSigma2: skip past nested
		// containers (e.g. the optional ResponderSessionParams structure)
		// instead of misreading their contents as top-level fields.
		if depth > 0 {
			if elem.Type().IsContainer() {
				depth++
			}
			continue
		}
		if elem.Type().IsContainer() {
			depth++
			continue
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

// topLevelFields decodes a TLV structure and returns its top-level octet
// string and unsigned fields by context tag, skipping the contents of
// nested containers such as the session parameters.
func topLevelFields(b []byte, what string) (map[uint8][]byte, map[uint8]uint64, error) {
	dec := tlv.NewDecoderWithBytes(b)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		return nil, nil, fmt.Errorf("case: %s: expected a structure", what)
	}
	octets := map[uint8][]byte{}
	uints := map[uint8]uint64{}
	depth := 0
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			if depth == 0 {
				return octets, uints, nil
			}
			depth--
			continue
		}
		if elem.Type().IsContainer() {
			depth++
			continue
		}
		if 0 < depth {
			continue
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if !ok {
			continue
		}
		tag := uint8(ct.ContextNumber())
		if v, ok := elem.Bytes(); ok {
			octets[tag] = cloneBytes(v)
		} else if v, ok := elem.Unsigned(); ok {
			uints[tag] = v
		}
	}
	if err := dec.Error(); err != nil {
		return nil, nil, fmt.Errorf("case: %s: %w", what, err)
	}
	return nil, nil, fmt.Errorf("case: %s: unterminated structure", what)
}

// decodeSigma1 decodes a Sigma1 (Matter Core 4.14.2.3). The resumption
// fields are ignored: this responder always answers with a full Sigma2.
func decodeSigma1(b []byte) (sigma1, error) {
	octets, uints, err := topLevelFields(b, "Sigma1")
	if err != nil {
		return sigma1{}, err
	}
	out := sigma1{
		InitiatorRandom:    octets[1],
		InitiatorSessionID: 0,
		DestinationID:      octets[3],
		InitiatorEphPubKey: octets[4],
		InitiatorMRP:       decodeMRPParameters(b, 5),
	}
	sessionID, ok := uints[2]
	switch {
	case len(out.InitiatorRandom) != randomLen:
		return sigma1{}, fmt.Errorf("case: Sigma1: missing initiator random")
	case !ok || sessionID == 0 || 0xFFFF < sessionID:
		return sigma1{}, fmt.Errorf("case: Sigma1: invalid initiator session ID")
	case len(out.DestinationID) != destinationIDLen:
		return sigma1{}, fmt.Errorf("case: Sigma1: missing destination ID")
	case len(out.InitiatorEphPubKey) != ephPubKeyLen:
		return sigma1{}, fmt.Errorf("case: Sigma1: missing initiator ephemeral public key")
	}
	out.InitiatorSessionID = uint16(sessionID)
	return out, nil
}

func encodeSigma2(v sigma2) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), v.ResponderRandom); err != nil {
		return nil, err
	}
	enc.PutUnsigned2(tlv.NewContextTag(2), v.ResponderSessionID)
	if err := enc.PutOctet(tlv.NewContextTag(3), v.ResponderEphPubKey); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(4), v.Encrypted2); err != nil {
		return nil, err
	}
	encodeSessionParams(enc, tlv.NewContextTag(5), defaultSessionParams)
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return cloneBytes(enc.Bytes()), nil
}

func encodeSigma2TBEData(v sigma2TBEData) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), v.ResponderNOC); err != nil {
		return nil, err
	}
	if len(v.ResponderICAC) != 0 {
		if err := enc.PutOctet(tlv.NewContextTag(2), v.ResponderICAC); err != nil {
			return nil, err
		}
	}
	if err := enc.PutOctet(tlv.NewContextTag(3), v.Signature); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(4), v.ResumptionID); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return cloneBytes(enc.Bytes()), nil
}

func decodeSigma3(b []byte) (sigma3, error) {
	octets, _, err := topLevelFields(b, "Sigma3")
	if err != nil {
		return sigma3{}, err
	}
	if len(octets[1]) == 0 {
		return sigma3{}, fmt.Errorf("case: Sigma3: missing encrypted3")
	}
	return sigma3{Encrypted3: octets[1]}, nil
}

func decodeSigma3TBEData(b []byte) (sigma3TBEData, error) {
	octets, _, err := topLevelFields(b, "Sigma3 encrypted payload")
	if err != nil {
		return sigma3TBEData{}, err
	}
	out := sigma3TBEData{InitiatorNOC: octets[1], InitiatorICAC: octets[2], Signature: octets[3]}
	if len(out.InitiatorNOC) == 0 {
		return sigma3TBEData{}, fmt.Errorf("case: Sigma3 encrypted payload missing initiator NOC")
	}
	if len(out.Signature) != signatureLen {
		return sigma3TBEData{}, fmt.Errorf("case: Sigma3 encrypted payload missing signature")
	}
	return out, nil
}

// decodeMRPParameters returns the MRP parameters of the
// session-parameter-struct at the top-level context tag of the structure
// b, with defaults for those it leaves out or which are absent (4.13.1.
// Session Parameters: SESSION_IDLE_INTERVAL at tag 1, SESSION_ACTIVE_INTERVAL
// at tag 2, in milliseconds, and SESSION_ACTIVE_THRESHOLD at tag 3).
func decodeMRPParameters(b []byte, tag uint8) session.MRPParameters {
	var p session.MRPParameters
	dec := tlv.NewDecoderWithBytes(b)
	if !dec.Next() || !dec.Element().Type().IsStructure() {
		return p.WithDefaults()
	}
	depth, inParams := 0, false
	for dec.Next() {
		elem := dec.Element()
		if elem.Type().IsEndOfContainer() {
			if depth == 0 {
				break
			}
			depth--
			inParams = false
			continue
		}
		ct, ok := elem.Tag().(tlv.ContextTag)
		if elem.Type().IsContainer() {
			depth++
			inParams = depth == 1 && ok && uint8(ct.ContextNumber()) == tag && elem.Type().IsStructure()
			continue
		}
		if !inParams || depth != 1 || !ok {
			continue
		}
		v, ok := elem.Unsigned()
		if !ok {
			continue
		}
		ms := time.Duration(min(v, uint64(session.MaxSessionInterval/time.Millisecond)+1)) * time.Millisecond // nolint: gosec // bounded above
		switch ct.ContextNumber() {
		case 1:
			p.IdleInterval = ms
		case 2:
			p.ActiveInterval = ms
		case 3:
			p.ActiveThreshold = ms
		}
	}
	return p.WithDefaults()
}
