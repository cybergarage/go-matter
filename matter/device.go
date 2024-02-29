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

	"github.com/cybergarage/go-safecast/safecast"
)

// DeviceType represents a device type.
type DeviceType uint

const (
	// DeviceTypeUnknown represents an unknown device type.
	DeviceTypeUnknown DeviceType = 0
)

// NewDeviceTypeFromString returns a new device type from a string.
func NewDeviceTypeFromString(s string) (DeviceType, error) {
	dti, err := strconv.Atoi(s)
	if err != nil {
		return DeviceTypeUnknown, err
	}
	var dt uint
	if err := safecast.ToUint(dti, &dt); err != nil {
		return DeviceTypeUnknown, err
	}
	return DeviceType(dt), nil
}
