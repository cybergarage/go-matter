// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package im

// Status is an Interaction Model status code (Matter Core 8.10).
type Status uint8

// Interaction Model status codes (Matter Core 8.10.1).
const (
	StatusSuccess                Status = 0x00
	StatusFailure                Status = 0x01
	StatusInvalidSubscription    Status = 0x7D
	StatusUnsupportedAccess      Status = 0x7E
	StatusUnsupportedEndpoint    Status = 0x7F
	StatusInvalidAction          Status = 0x80
	StatusUnsupportedCommand     Status = 0x81
	StatusInvalidCommand         Status = 0x85
	StatusUnsupportedAttribute   Status = 0x86
	StatusConstraintError        Status = 0x87
	StatusUnsupportedWrite       Status = 0x88
	StatusResourceExhausted      Status = 0x89
	StatusNotFound               Status = 0x8B
	StatusUnreportableAttribute  Status = 0x8C
	StatusInvalidDataType        Status = 0x8D
	StatusUnsupportedRead        Status = 0x8F
	StatusDataVersionMismatch    Status = 0x92
	StatusTimeout                Status = 0x94
	StatusBusy                   Status = 0x9C
	StatusUnsupportedCluster     Status = 0xC3
	StatusNoUpstreamSubscription Status = 0xC5
	StatusNeedsTimedInteraction  Status = 0xC6
	StatusUnsupportedEvent       Status = 0xC7
	StatusPathsExhausted         Status = 0xC8
	StatusTimedRequestMismatch   Status = 0xC9
	StatusFailsafeRequired       Status = 0xCA
	StatusInvalidInState         Status = 0xCB
	StatusNoCommandResponse      Status = 0xCC
)
