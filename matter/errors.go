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

package matter

import (
	stderrors "errors"

	"github.com/cybergarage/go-matter/matter/errors"
)

var (
	// ErrNotFound is returned when a requested resource is not found.
	ErrNotFound = errors.ErrNotFound
	// ErrFailed is returned when an operation fails.
	ErrFailed = errors.ErrFailed
	// ErrWiFiNetworkRequired is returned when a device found over BLE is
	// commissioned without the Wi-Fi network credentials to give it: it
	// joins no operational network otherwise (5.5. Commissioning Flows,
	// steps 12-13).
	ErrWiFiNetworkRequired = stderrors.New("commissioning over BLE requires the Wi-Fi network credentials")
	// ErrNotInCommissioningMode is returned when the device was found on the
	// network, but advertises that it is not in commissioning mode (CM=0):
	// it has no commissioning window open, and would not answer PASE. A
	// window is opened on the device itself (a power cycle or a factory
	// reset, by its maker's instructions), or by an administrator of a fabric
	// it is already in. 4.3.1.7. TXT key for commissioning mode (CM).
	ErrNotInCommissioningMode = stderrors.New("the device is not in commissioning mode (CM=0): open a commissioning window on it, or reset it to factory defaults")
)
