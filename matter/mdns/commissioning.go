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

package mdns

import (
	"strconv"

	"github.com/cybergarage/go-safecast/safecast"
)

// CommissioningMode represents the commissioning mode type.
// 4.3.1.7. TXT key for commissioning mode (CM).
type CommissioningMode int

const (
	CommissioningModeAbsence             = CommissioningMode(0)
	CommissioningModePasscode            = CommissioningMode(1)
	CommissioningModeDynamicPasscode     = CommissioningMode(2)
	CommissioningModeJointFabricPasscode = CommissioningMode(3)
)

// NewCommissioningModeFrom creates a CommissioningMode from any value.
func NewCommissioningModeFrom(v any) (CommissioningMode, error) {
	var cm int
	if err := safecast.ToInt(v, &cm); err != nil {
		return CommissioningModeAbsence, err
	}
	return CommissioningMode(cm), nil
}

// String returns the string representation of the commissioning mode.
func (cm CommissioningMode) String() string {
	return strconv.Itoa(int(cm))
}
