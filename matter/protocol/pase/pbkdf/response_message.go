// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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
	"github.com/cybergarage/go-matter/matter/encoding/json"
	"github.com/cybergarage/go-matter/matter/encoding/message"
)

type paramResponseMessage struct {
	Message
	ParamResponse
}

// NewParamResponseMessageFromBytes parses the given byte slice into a ParamResponseMessage.
func NewParamResponseMessageFromBytes(data []byte) (ParamResponseMessage, error) {
	msg, err := message.NewMessageFromBytes(data)
	if err != nil {
		return nil, err
	}

	paramReq, err := NewParamResponseFromBytes(msg.Payload())
	if err != nil {
		return nil, err
	}

	return &paramResponseMessage{
		Message:       msg,
		ParamResponse: paramReq,
	}, nil
}

func (r *paramResponseMessage) Bytes() ([]byte, error) {
	return r.Message.Bytes()
}

func (r *paramResponseMessage) Map() map[string]any {
	return map[string]any{
		"message":              r.Message.Map(),
		"pbkdfparamres-struct": r.ParamResponse.Map(),
	}
}

func (r *paramResponseMessage) String() string {
	return json.MustMarshal(r.Map())
}
