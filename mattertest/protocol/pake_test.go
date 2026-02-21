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
	_ "embed"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/protocol"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pake"
)

//go:embed dumps/pase-01-pake1.hex
var pake101Hex string

//go:embed dumps/pase-01-pake2.hex
var pake201Hex string

//go:embed dumps/pase-01-pake3.hex
var pake301Hex string

func TestPake1(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pake101Hex,
		},
	}

	for n, tt := range tests {
		t.Run(fmt.Sprintf("pak1-%02d", n), func(t *testing.T) {
			hexBytes, err := hex.DecodeString(tt.hexStr)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}
			msg, err := protocol.NewMessageFromBytes(hexBytes)
			if err != nil {
				t.Fatalf("Failed to parse Message: %v", err)
			}

			reqParam, err := pake.NewPake1FromBytes(msg.Payload())
			if err != nil {
				t.Errorf("Failed to parse ParamRequest: %v", err)
				log.HexInfo(hexBytes)
				log.Info(msg.String())
				log.Info(reqParam.String())
			}
		})
	}
}

func TestPake2(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pake201Hex,
		},
	}

	for n, tt := range tests {
		t.Run(fmt.Sprintf("pak2-%02d", n), func(t *testing.T) {
			hexBytes, err := hex.DecodeString(tt.hexStr)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}
			msg, err := protocol.NewMessageFromBytes(hexBytes)
			if err != nil {
				t.Fatalf("Failed to parse Message: %v", err)
			}

			reqParam, err := pake.NewPake2FromBytes(msg.Payload())
			if err != nil {
				t.Errorf("Failed to parse ParamRequest: %v", err)
				log.HexInfo(hexBytes)
				log.Info(msg.String())
				log.Info(reqParam.String())
			}
		})
	}
}

func TestPake3(t *testing.T) {
	log.EnableStdoutDebug(true)

	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pake301Hex,
		},
	}

	for n, tt := range tests {
		t.Run(fmt.Sprintf("pak3-%02d", n), func(t *testing.T) {
			hexBytes, err := hex.DecodeString(tt.hexStr)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}
			msg, err := protocol.NewMessageFromBytes(hexBytes)
			if err != nil {
				t.Fatalf("Failed to parse Message: %v", err)
			}

			reqParam, err := pake.NewPake3FromBytes(msg.Payload())
			if err != nil {
				t.Errorf("Failed to parse ParamRequest: %v", err)
				log.HexInfo(hexBytes)
				log.Info(msg.String())
				log.Info(reqParam.String())
			}
		})
	}
}
