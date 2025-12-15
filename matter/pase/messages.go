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

// Pake1 represents the first PASE message (prover's public share).
type Pake1 struct {
	// X is the prover's public share (SPAKE2+ X value).
	X []byte
}

// NewPake1 creates a new Pake1 message.
func NewPake1(x []byte) *Pake1 {
	return &Pake1{X: x}
}

// Bytes returns the byte representation of the Pake1 message.
// TODO: Migrate to encoding/tlv for proper TLV encoding per Matter specification.
// Current implementation uses simple concatenation: opcode + X
func (p *Pake1) Bytes() []byte {
	result := make([]byte, 1+len(p.X))
	result[0] = opPASEPake1
	copy(result[1:], p.X)
	return result
}

// Pake2 represents the second PASE message (verifier's public share and confirmation).
type Pake2 struct {
	// Y is the verifier's public share (SPAKE2+ Y value).
	Y []byte
	// CMac is the verifier's confirmation MAC.
	CMac []byte
}

// NewPake2 creates a new Pake2 message.
func NewPake2(y, cmac []byte) *Pake2 {
	return &Pake2{
		Y:    y,
		CMac: cmac,
	}
}

// Bytes returns the byte representation of the Pake2 message.
// TODO: Migrate to encoding/tlv for proper TLV encoding per Matter specification.
// Current implementation uses simple concatenation: opcode + Y + CMac
func (p *Pake2) Bytes() []byte {
	result := make([]byte, 1+len(p.Y)+len(p.CMac))
	result[0] = opPASEPake2
	offset := 1
	copy(result[offset:], p.Y)
	offset += len(p.Y)
	copy(result[offset:], p.CMac)
	return result
}

// Pake3 represents the third PASE message (prover's confirmation).
type Pake3 struct {
	// SMac is the prover's confirmation MAC.
	SMac []byte
}

// NewPake3 creates a new Pake3 message.
func NewPake3(smac []byte) *Pake3 {
	return &Pake3{SMac: smac}
}

// Bytes returns the byte representation of the Pake3 message.
// TODO: Migrate to encoding/tlv for proper TLV encoding per Matter specification.
// Current implementation uses simple concatenation: opcode + SMac
func (p *Pake3) Bytes() []byte {
	result := make([]byte, 1+len(p.SMac))
	result[0] = opPASEPake3
	copy(result[1:], p.SMac)
	return result
}
