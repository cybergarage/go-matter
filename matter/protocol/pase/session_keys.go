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

// SessionKeys represents the session keys derived after a successful PASE session.
type SessionKeys interface {
	// I2RKey returns the initiator-to-responder AES-CCM key.
	I2RKey() []byte
	// R2IKey returns the responder-to-initiator AES-CCM key.
	R2IKey() []byte
	// AttestationChallenge returns the attestation challenge.
	AttestationChallenge() []byte
}

type sessionKeys struct {
	i2rKey               []byte
	r2iKey               []byte
	attestationChallenge []byte
}

func newSessionKeys(i2rKey, r2iKey, attestationChallenge []byte) SessionKeys {
	return &sessionKeys{
		i2rKey:               cloneBytes(i2rKey),
		r2iKey:               cloneBytes(r2iKey),
		attestationChallenge: cloneBytes(attestationChallenge),
	}
}

func (keys *sessionKeys) I2RKey() []byte {
	return cloneBytes(keys.i2rKey)
}

func (keys *sessionKeys) R2IKey() []byte {
	return cloneBytes(keys.r2iKey)
}

func (keys *sessionKeys) AttestationChallenge() []byte {
	return cloneBytes(keys.attestationChallenge)
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}
