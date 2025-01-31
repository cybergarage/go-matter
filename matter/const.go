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

package matter

const (
	Port = 5540
)

// Matter Specification Version 1.2
// 4.3.1.3. Commissioning Subtypes.
const (
	SubtypeDiscriminatorLong  = "_L"
	SubtypeDiscriminatorShort = "_S"
	SubtypeVendorID           = "_V"
	SubtypeDeviceType         = "_T"
	SubtypeCommissioningMode  = "_CM"
)

// Matter Specification Version 1.2
// 4.3.1.4. TXT Records.
const (
	TxtRecordDiscriminator      = "D"
	TxtRecordVendorProductID    = "VP"
	TxtRecordCommissioningMode  = "CM"
	TxtRecordDeviceType         = "DT"
	TxtRecordDeviceName         = "DN"
	TxtRecordRotatingDeviceID   = "RI"
	TxtRecordPairingHint        = "PH"
	TxtRecordPairingInstruction = "PI"
)

// Matter Specification Version 1.2
// 4.3.1.7. TXT key for commissioning mode (CM).
const (
	CommissioningModeNone = "0"
	CommissioningMode1    = "1"
	CommissioningMode2    = "2"
)
