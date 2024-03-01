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

// GroupID represents a group ID.
type GroupID = message.GroupID

const (
	UnspecifiedGroupID            GroupID = 0x0000
	UniversalGroupIDMin           GroupID = 0xFF00
	UniversalGroupIDMax           GroupID = 0xFFFF
	UniversalAllNodeGroupID       GroupID = 0xFFFF
	UniversalAllNonICDNodeGroupID GroupID = 0xFFFE
	UniversalAllProxyGroupID      GroupID = 0xFFFD
	ApplicationGroupIDMin         GroupID = 0x0001
	ApplicationGroupIDMax         GroupID = 0xFEFF
)
