// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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

package protocol

import (
	"fmt"
	"testing"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
)

func TestPBKDFParamRequestMessage(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		msg pbkdf.ParamRequestMessage
	}{
		{
			msg: decodeHexdumpPBKDFParamRequestMessage(t, pbkdfParamRequest01Hex),
		},
		{
			msg: func() pbkdf.ParamRequestMessage {
				msg, err := pbkdf.NewParamRequestMessage()
				if err != nil {
					t.Fatal(err)
				}
				return msg
			}(),
		},
	}

	for n, tt := range tests {
		name := fmt.Sprintf("pbkdf-param-request-%02d", n)
		t.Run(name, func(t *testing.T) {
			msg := tt.msg
			if err := validatePBKDFParamRequest(msg); err != nil {
				t.Errorf("Validation failed: %v", err)
			}
			reqParam, err := pbkdf.NewParamRequestFromBytes(msg.Payload())
			if err != nil {
				t.Errorf("Failed to parse ParamRequest: %v", err)
			}
			log.Infof("%s %s", name, msg.String())
			log.Infof("%s %s", name, reqParam.String())
		})
	}
}

func TestPBKDFParamResponseMessage(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		msg message.Message
	}{
		{
			msg: decodeHexdumpMessage(t, pbkdfParamResponse01Hex),
		},
	}

	for n, tt := range tests {
		name := fmt.Sprintf("pbkdf-param-response-%02d", n)
		t.Run(name, func(t *testing.T) {
			msg := tt.msg
			if err := validatePBKDFParamResponse(msg); err != nil {
				t.Errorf("Validation failed: %v", err)
			}
			resParam, err := pbkdf.NewParamResponseFromBytes(msg.Payload())
			if err != nil {
				t.Errorf("Failed to parse ParamResponse: %v", err)
			}
			log.Infof("%s %s", name, msg.String())
			log.Infof("%s %s", name, resParam.String())
		})
	}
}
