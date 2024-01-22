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

package message

// 4.4.1. Message Header Field Descriptions
// Header represents a message header.
type Header struct {
	Length            uint16
	Flag              Flag
	SessionId         SessionId
	SecurityFlag      SecurityFlag
	Counter           Counter
	SourceNodeId      NodeId
	DestinationNodeId NodeId
}
