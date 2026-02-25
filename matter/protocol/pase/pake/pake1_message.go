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

type pake1Message struct {
	Message
	Pake1
}

// NewPake1MessageFromBytes creates a new Pake1Message from the given byte slice, which is expected to be a valid message containing a Pake1 payload.
func NewPake1MessageFromBytes(data []byte) (Pake1Message, error) {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return nil, err
	}
	pake, err := NewPake1FromBytes(msg.Payload())
	if err != nil {
		return nil, err
	}

	return &pake1Message{
		Message: msg,
		Pake1:   pake,
	}, nil
}

func (m *pake1Message) Bytes() ([]byte, error) {
	return m.Message.Bytes()
}

func (m *pake1Message) Map() map[string]any {
	return map[string]any{
		"message":       m.Message.Map(),
		"pake-1-struct": m.Pake1.Map(),
	}
}

func (m *pake1Message) String() string {
	return json.MustMarshal(m.Map())
}
