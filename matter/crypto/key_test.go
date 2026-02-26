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

package crypto

import (
	"testing"
)

func TestCryptoGenerateKeypair(t *testing.T) {
	kp, err := CryptoGenerateKeyPair()
	if err != nil {
		t.Fatalf("CryptoGenerateKeypair returned error: %v", err)
	}
	if kp.Private() == nil {
		t.Error("Expected non-nil PrivateKey")
	}
	if kp.Public() == nil {
		t.Error("Expected non-nil PublicKey")
		return
	}
	pubBytes, err := kp.Public().Bytes()
	if err != nil {
		t.Errorf("PublicKey.Bytes() returned error: %v", err)
	}
	if len(pubBytes) != CryptoPublicKeySizeBytes {
		t.Errorf("PublicKey.Bytes() returned %d bytes, expected %d", len(pubBytes), CryptoPublicKeySizeBytes)
	}
}
