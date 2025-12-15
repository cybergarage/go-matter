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

package pase

// Pake1 represents the PASE PAKE1 message (first message in PASE handshake).
// This message contains the prover's (client's) public value X.
type Pake1 struct {
	// X is the prover's public value (SPAKE2+ X point in SEC1 uncompressed form).
	X []byte
}

// NewPake1 creates a new Pake1 message with the given public value.
func NewPake1(x []byte) *Pake1 {
	return &Pake1{X: x}
}

// Bytes returns the byte representation of the Pake1 message.
// The message format is: opcode (1 byte) || X (65 bytes for P-256 uncompressed point).
// TODO: Migrate to encoding.tlv for proper TLV encoding per Matter specification.
func (p *Pake1) Bytes() []byte {
	// Prefix with opPASEPake1 opcode
	result := make([]byte, 1+len(p.X))
	result[0] = opPASEPake1
	copy(result[1:], p.X)
	return result
}

// Pake2 represents the PASE PAKE2 message (second message in PASE handshake).
// This message contains the verifier's (server's) public value Y and confirmation MAC.
type Pake2 struct {
	// Y is the verifier's public value (SPAKE2+ Y point in SEC1 uncompressed form).
	Y []byte
	// CMac is the verifier's confirmation MAC.
	CMac []byte
}

// NewPake2 creates a new Pake2 message with the given public value and confirmation MAC.
func NewPake2(y, cmac []byte) *Pake2 {
	return &Pake2{Y: y, CMac: cmac}
}

// Bytes returns the byte representation of the Pake2 message.
// The message format is: opcode (1 byte) || Y || CMac.
// TODO: Migrate to encoding.tlv for proper TLV encoding per Matter specification.
func (p *Pake2) Bytes() []byte {
	// Prefix with opPASEPake2 opcode
	result := make([]byte, 1+len(p.Y)+len(p.CMac))
	result[0] = opPASEPake2
	copy(result[1:], p.Y)
	copy(result[1+len(p.Y):], p.CMac)
	return result
}

// Pake3 represents the PASE PAKE3 message (third message in PASE handshake).
// This message contains the prover's (client's) confirmation MAC.
type Pake3 struct {
	// SMac is the prover's confirmation MAC.
	SMac []byte
}

// NewPake3 creates a new Pake3 message with the given confirmation MAC.
func NewPake3(smac []byte) *Pake3 {
	return &Pake3{SMac: smac}
}

// Bytes returns the byte representation of the Pake3 message.
// The message format is: opcode (1 byte) || SMac.
// TODO: Migrate to encoding.tlv for proper TLV encoding per Matter specification.
func (p *Pake3) Bytes() []byte {
	// Prefix with opPASEPake3 opcode
	result := make([]byte, 1+len(p.SMac))
	result[0] = opPASEPake3
	copy(result[1:], p.SMac)
	return result
}
