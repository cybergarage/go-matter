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
	"github.com/cybergarage/go-matter/matter/protocol/mrp"
)

func TestMRPMessage(t *testing.T) {
	log.EnableStdoutDebug(true)

	type expected struct {
		messageCounter mrp.MessageCounter
	}

	tests := []struct {
		hexStr   string
		expected expected
	}{
		{
			hexStr: mrp01Hex,
			expected: expected{
				messageCounter: 0xF0E9E46,
			},
		},
		{
			hexStr: mrp02Hex,
			expected: expected{
				messageCounter: 0xF0E9E48,
			},
		},
	}

	for n, tt := range tests {
		t.Run(fmt.Sprintf("mrp-%02d", n), func(t *testing.T) {
			hexBytes, err := hex.DecodeString(tt.hexStr)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}
			ack, err := mrp.NewAckFromBytes(hexBytes)
			if err != nil {
				t.Fatalf("Failed to parse Message: %v", err)
			}

			if err := validateAckMessage(ack); err != nil {
				t.Errorf("Validation failed: %v", err)
			}

			if ack.MessageCounter() != tt.expected.messageCounter {
				t.Errorf("Expected messageCounter 0x%04X, got 0x%04X", tt.expected.messageCounter, ack.MessageCounter())
				log.Infof("ACK: %s", ack.String())
			}

			log.Infof("ACK: %s", ack.String())
		})
	}
}
