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

const (
	// CryptoHashLenBytes defines the length of the hash output in bytes for the CryptoHash function.
	// 3.3. Hash function (Hash).
	CryptoHashLenBytes = 32
	// CryptoGroupSizeBytes defines the size of the group elements in bytes for the CryptoGroup operations.
	// 3.5. Public Key Cryptography.
	CryptoGroupSizeBytes = 32
	// CryptoPublicKeySizeBytes defines the size of the public key in bytes for the CryptoGroup operations.
	// 3.5. Public Key Cryptography.
	CryptoPublicKeySizeBytes = (CryptoGroupSizeBytes * 2) + 1
)
