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

package pake

import (
	"github.com/cybergarage/go-matter/matter/encoding/json"
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

type pake3Message struct {
	Message
	Pake3
}

// NewPake3MessageFromBytes creates a new Pake3Message from the given byte slice, which is expected to be a valid message containing a Pake3 payload.
func NewPake3MessageFromBytes(data []byte) (Pake3Message, error) {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return nil, err
	}
	pake, err := NewPake3FromBytes(msg.Payload())
	if err != nil {
		return nil, err
	}
	return &pake3Message{
		Message: msg,
		Pake3:   pake,
	}, nil
}

func (m *pake3Message) Bytes() ([]byte, error) {
	return m.Message.Bytes()
}

func (m *pake3Message) Map() map[string]any {
	return map[string]any{
		"message":       m.Message.Map(),
		"pake-2-struct": m.Pake3.Map(),
	}
}

func (m *pake3Message) String() string {
	return json.MustMarshal(m.Map())
}
