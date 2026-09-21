// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package btp

import "fmt"

// 4.19.4.4. BTP Data Packet Header. Masks for the BTP fragment header flag
// byte, matching the reference implementation's BtpEngine::HeaderFlags.
const (
	headerFlagStartMessage    = 0x01
	headerFlagContinueMessage = 0x02
	headerFlagEndMessage      = 0x04
	headerFlagFragmentAck     = 0x08
)

// Segmenter implements the BTP data-segment framing used to exchange Matter
// messages over C1/C2 after the initial handshake, for the central
// (initiator) role only. As the central, this role's own sequence numbers
// start at 0 and the peripheral's are expected to start at 1 (4.19.4.5,
// matching the reference implementation's BLEEndPoint::Init, which passes
// expectInitialAck as (role == kBleRole_Peripheral)).
//
// Acknowledgements are only ever piggybacked on the next outgoing segment,
// never sent standalone: the commissioning exchanges this is used for are
// strictly alternating request/response, so there is always a next outgoing
// message to carry the ack on.
type Segmenter struct {
	fragmentSize  int
	txNextSeq     uint8
	rxNextSeq     uint8
	pendingAckSeq uint8
	hasPendingAck bool
	rxBuf         []byte
	rxMsgLen      int
}

// NewSegmenter returns a new Segmenter using the given negotiated BTP
// fragment size (HandshakeResponse.FragmentSize()).
func NewSegmenter(fragmentSize int) *Segmenter {
	return &Segmenter{
		fragmentSize: fragmentSize,
		txNextSeq:    0,
		rxNextSeq:    1,
	}
}

// EncodeMessage splits a Matter message into one or more BTP data segments,
// to be written to C1 in order.
func (s *Segmenter) EncodeMessage(payload []byte) [][]byte {
	var segments [][]byte
	remaining := payload
	first := true
	for {
		headerSize := 2 // header flags + sequence number
		if first {
			headerSize += 2 // message length, start-of-message only
		}
		if s.hasPendingAck {
			headerSize++
		}
		capacity := s.fragmentSize - headerSize
		n := len(remaining)
		last := n <= capacity
		if !last {
			n = capacity
		}
		chunk := remaining[:n]
		remaining = remaining[n:]

		var flags byte
		if first {
			flags |= headerFlagStartMessage
		} else {
			flags |= headerFlagContinueMessage
		}
		if last {
			flags |= headerFlagEndMessage
		}

		seg := make([]byte, 0, headerSize+len(chunk))
		if s.hasPendingAck {
			flags |= headerFlagFragmentAck
			seg = append(seg, flags, s.pendingAckSeq)
			s.hasPendingAck = false
		} else {
			seg = append(seg, flags)
		}
		seg = append(seg, s.txNextSeq)
		s.txNextSeq++
		if first {
			seg = append(seg, byte(len(payload)), byte(len(payload)>>8))
		}
		seg = append(seg, chunk...)
		segments = append(segments, seg)

		first = false
		if last {
			break
		}
	}
	return segments
}

// Feed processes one received raw BTP segment. Once the final fragment of a
// message has been fed, it returns the fully reassembled message and
// ok == true; until then, ok is false and message is nil.
func (s *Segmenter) Feed(seg []byte) ([]byte, bool, error) {
	if len(seg) < 2 {
		return nil, false, fmt.Errorf("btp: segment too short: %d bytes", len(seg))
	}

	flags := seg[0]
	i := 1
	if flags&headerFlagFragmentAck != 0 {
		i++ // ack number: nothing to retransmit, so it's unused
	}
	if i >= len(seg) {
		return nil, false, fmt.Errorf("btp: segment missing sequence number")
	}
	seqNum := seg[i]
	i++

	if seqNum != s.rxNextSeq {
		return nil, false, fmt.Errorf("btp: unexpected sequence number %d, want %d", seqNum, s.rxNextSeq)
	}
	s.rxNextSeq++
	s.pendingAckSeq = seqNum
	s.hasPendingAck = true

	isStart := flags&headerFlagStartMessage != 0
	isContinue := flags&headerFlagContinueMessage != 0
	isEnd := flags&headerFlagEndMessage != 0
	if !isStart && !isContinue && !isEnd {
		return nil, false, nil // standalone ack, no payload
	}

	if isStart {
		if i+2 > len(seg) {
			return nil, false, fmt.Errorf("btp: segment missing message length")
		}
		s.rxMsgLen = int(seg[i]) | int(seg[i+1])<<8
		i += 2
		s.rxBuf = make([]byte, 0, s.rxMsgLen)
	}
	s.rxBuf = append(s.rxBuf, seg[i:]...)

	if !isEnd {
		return nil, false, nil
	}

	msg := s.rxBuf
	s.rxBuf = nil
	if len(msg) != s.rxMsgLen {
		return nil, false, fmt.Errorf("btp: reassembled message length %d, want %d", len(msg), s.rxMsgLen)
	}
	return msg, true, nil
}
