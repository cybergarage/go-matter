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

func TestPaseSequence(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		pbkdfParamReq message.Message
		pbkdfParamRes message.Message
	}{
		{
			pbkdfParamReq: decodeHexdumpPBKDFParamRequestMessage(t, pbkdfParamRequest01Hex),
			pbkdfParamRes: decodeHexdumpPBKDFParamResponseMessage(t, pbkdfParamResponse01Hex),
		},
		{
			pbkdfParamReq: func() message.Message {
				msg, err := pbkdf.NewParamRequestMessage()
				if err != nil {
					t.Fatal(err)
				}
				return msg
			}(),
			pbkdfParamRes: nil,
		},
	}

	// 4.14.1. Passcode-Authenticated Session Establishment (PASE)
	// 4.14.1.2. Protocol Details
	for n, tt := range tests {
		name := fmt.Sprintf("pase-%02d", n)
		t.Run(name, func(t *testing.T) {
			name := fmt.Sprintf("pbkdf-param-request-%02d", n)
			pbkdfParamReq := tt.pbkdfParamReq
			t.Run(name, func(t *testing.T) {
				// PBKDF Parameter Request
				if err := validatePBKDFParamRequest(pbkdfParamReq); err != nil {
					t.Errorf("Validation failed: %v", err)
				}
				log.Infof("%s %s", name, pbkdfParamReq.String())
			})

			name = fmt.Sprintf("pbkdf-param-response-%02d", n)
			t.Run(name, func(t *testing.T) {
				// PBKDF Parameter Response
				pbkdfParamRes := tt.pbkdfParamRes
				if pbkdfParamRes == nil {
					t.Skip("Skipping test as pbkdfParamRes is nil")
				}
				if err := validatePBKDFParamResponse(pbkdfParamRes); err != nil {
					t.Errorf("Validation failed: %v", err)
				}
				log.Infof("%s %s", name, pbkdfParamRes.String())
			})
		})
	}
}
