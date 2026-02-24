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
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pake"
)

func TestPake1Message(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pake101Hex,
		},
	}

	for n, tt := range tests {
		t.Run(fmt.Sprintf("pake1-%02d", n), func(t *testing.T) {
			hexBytes, err := hex.DecodeString(tt.hexStr)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}
			msg, err := pake.NewPake1MessageFromBytes(hexBytes)
			if err != nil {
				t.Fatalf("Failed to parse Pake1Message: %v", err)
			}
			if err != nil {
				t.Errorf("Failed to parse ParamRequest: %v", err)
				log.HexInfo(hexBytes)
			}
			log.Infof("pake1: %s", msg.String())
		})
	}
}

func TestPake2Message(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pake201Hex,
		},
	}

	for n, tt := range tests {
		t.Run(fmt.Sprintf("pake2-%02d", n), func(t *testing.T) {
			hexBytes, err := hex.DecodeString(tt.hexStr)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}
			msg, err := pake.NewPake2MessageFromBytes(hexBytes)
			if err != nil {
				t.Fatalf("Failed to parse Pake2Message: %v", err)
			}
			if err != nil {
				t.Errorf("Failed to parse ParamRequest: %v", err)
				log.HexInfo(hexBytes)
			}
			log.Infof("pake2: %s", msg.String())
		})
	}
}

func TestPake3Message(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pake301Hex,
		},
	}

	for n, tt := range tests {
		t.Run(fmt.Sprintf("pake3-%02d", n), func(t *testing.T) {
			hexBytes, err := hex.DecodeString(tt.hexStr)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}
			msg, err := pake.NewPake3MessageFromBytes(hexBytes)
			if err != nil {
				t.Fatalf("Failed to parse Pake3Message: %v", err)
			}
			if err != nil {
				t.Errorf("Failed to parse ParamRequest: %v", err)
				log.HexInfo(hexBytes)
			}
			log.Infof("pake3: %s", msg.String())
		})
	}
}
