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

// GroupId represents a group ID.
type GroupId uint16

const (
	UnspecifiedGroupId            = (GroupId)(0x0000)
	UniversalGroupIdMin           = (GroupId)(0xFF00)
	UniversalGroupIdMax           = (GroupId)(0xFFFF)
	UniversalAllNodeGroupId       = (GroupId)(0xFFFF)
	UniversalAllNonICDNodeGroupId = (GroupId)(0xFFFE)
	UniversalAllProxyGroupId      = (GroupId)(0xFFFD)
	ApplicationGroupIDMin         = (GroupId)(0x0001)
	ApplicationGroupIDMax         = (GroupId)(0xFEFF)
)
