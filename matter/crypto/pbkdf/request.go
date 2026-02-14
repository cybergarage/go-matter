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
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// EncodePBKDFParamRequest encodes a PBKDFParamRequest TLV payload (TLV only; no opcode).
func EncodePBKDFParamRequest() ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.StartStructure(tlv.AnonymousTag())

	// TODO(spec): Add mandatory fields if the target device requires them
	// (e.g., initiator random, session parameters, etc.).
	// Keeping this structure empty is useful as a first connectivity probe.

	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	enc.MustEndAll()
	return enc.Bytes(), nil
}
