// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package pbkdf

import (
	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// 3.9. Password-Based Key Derivation Function (PBKDF).
const (
	PBKDBFIterationsMin = crypto.PBKDBFIterationsMin
	PBKDBFIterationsMax = crypto.PBKDBFIterationsMax
	PBKDBFSaltMin       = crypto.PBKDBFSaltMin
	PBKDBFSaltMax       = crypto.PBKDBFSaltMax
)

// CryptoPBKDFParameterSet encodes the PBKDF parameters into the given TLV encoder according to the Matter specification.
// 3.9. Password-Based Key Derivation Function (PBKDF).
func CryptoPBKDFParameterSet(enc tlv.Encoder, tarOrder uint8, params Params) error {
	enc.BeginStructure(tlv.NewContextTag(tarOrder))
	if params != nil {
		iter, ok := params.Iterations()
		if ok {
			if iter < PBKDBFIterationsMin || PBKDBFIterationsMax < iter {
				return tlv.NewErrInvalidField("iterations", iter)
			}
			enc.PutUnsigned2(tlv.NewContextTag(pbkdfTagIterations), uint16(iter))
		}
		salt, ok := params.Salt()
		if ok {
			saltLen := len(salt)
			if saltLen < PBKDBFSaltMin || PBKDBFSaltMax < saltLen {
				return tlv.NewErrInvalidField("salt", salt)
			}
			enc.PutOctet(tlv.NewContextTag(pbkdfTagSalt), salt)
		}
	}
	return enc.EndContainer()
}
