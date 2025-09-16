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

package ble

import (
	"github.com/cybergarage/go-ble/ble"
)

// 4.19.4.2. BTP GATT Service

const (
	C1MaxDataLen = 247
	C2MaxDataLen = 247
	C3MaxDataLen = 512
)

var (
	C1UUID = ble.MustUUIDFromString("18EE2EF5-263D-4559-959F-4F9C429F9D11")
	C2UUID = ble.MustUUIDFromString("18EE2EF5-263D-4559-959F-4F9C429F9D12")
	C3UUID = ble.MustUUIDFromString("64630238-8772-45F2-B87D-748A83218F04")
)

// Characteristic represents a BLE characteristic.
type Characteristic = ble.Characteristic
