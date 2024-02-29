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

import (
	"strconv"
)

// PairingHint represents a pairing hint.
type PairingHint uint

const (
	PairingHintNone                                 (PairingHint) = 0x0000
	PairingHintPowerCycle                           (PairingHint) = 0x0001
	PairingHintDeviceManufacturerURL                (PairingHint) = 0x0002
	PairingHintAdministrator                        (PairingHint) = 0x0004
	PairingHintSettingsMenu                         (PairingHint) = 0x0008
	PairingHintCustomInstruction                    (PairingHint) = 0x0010
	PairingHintDeviceManual                         (PairingHint) = 0x0020
	PairingHintPressResetButton                     (PairingHint) = 0x0040
	PairingHintPressResetButtonWithfPower           (PairingHint) = 0x0080
	PairingHintPressResetButtonForNSeconds          (PairingHint) = 0x0100
	PairingHintPressResetButtonUntilLightBlinks     (PairingHint) = 0x0200
	PairingHintPressResetButtonForNSecondsWithPower (PairingHint) = 0x0400
)

// NewPairingHintFromString returns a new pairing hint from a string.
func NewPairingHintFromString(s string) (PairingHint, error) {
	ph, err := strconv.Atoi(s)
	if err != nil {
		return PairingHintNone, err
	}
	return PairingHint(ph), nil
}
