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

package crypto

import (
	_ "embed"
	"encoding/hex"
	"testing"
)

//go:embed dumps/pbkdf-param-request-01.hex
var pbkdfParamRequest01Hex string

//go:embed dumps/pbkdf-param-response-01.hex
var pbkdfParamResponse01Hex string

//go:embed dumps/pbkdf-param-response-02.hex
var pbkdfParamResponse02Hex string

func TestPBKDFParamRequest(t *testing.T) {
	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pbkdfParamRequest01Hex,
		},
	}

	for _, tt := range tests {
		_, err := hex.DecodeString(tt.hexStr)
		if err != nil {
			t.Fatalf("Failed to decode hex string: %v", err)
		}
	}
}

func TestPBKDFParamResponse(t *testing.T) {
	tests := []struct {
		hexStr string
	}{
		{
			hexStr: pbkdfParamResponse01Hex,
		},
		{
			hexStr: pbkdfParamResponse02Hex,
		},
	}

	for _, tt := range tests {
		_, err := hex.DecodeString(tt.hexStr)
		if err != nil {
			t.Fatalf("Failed to decode hex string: %v", err)
		}
	}
}
