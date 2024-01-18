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
	"github.com/cybergarage/go-matter/matter/message"
)

// VendorId represents a vendor ID.
type VenderId = message.VenderId

const (
	MatterStandardVenderId = (VenderId)(0x0000)
	TestVender01Id         = (VenderId)(0xFFF1)
	TestVender02Id         = (VenderId)(0xFFF2)
	TestVender03Id         = (VenderId)(0xFFF3)
	TestVender04Id         = (VenderId)(0xFFF4)
)
