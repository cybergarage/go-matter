// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package encoding

// CommissioningFlow represents the commissioning flow type.
type CommissioningFlow uint8

const (
	CommissioningFlowStandard   CommissioningFlow = 0
	CommissioningFlowUserAction CommissioningFlow = 1
	CommissioningFlowCustom     CommissioningFlow = 2
)

// IsStandard returns whether the commissioning flow is standard.
func (f CommissioningFlow) IsStandard() bool {
	return f == CommissioningFlowStandard
}

// IsUserAction returns whether the commissioning flow is user-action.
func (f CommissioningFlow) IsUserAction() bool {
	return f == CommissioningFlowUserAction
}

// IsCustom returns whether the commissioning flow is custom.
func (f CommissioningFlow) IsCustom() bool {
	return f == CommissioningFlowCustom
}

func (f CommissioningFlow) String() string {
	switch f {
	case CommissioningFlowStandard:
		return "standard"
	case CommissioningFlowUserAction:
		return "user-action"
	case CommissioningFlowCustom:
		return "custom"
	default:
		return "unknown"
	}
}
