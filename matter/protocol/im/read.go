// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

package im

import "github.com/cybergarage/go-matter/matter/encoding/tlv"

// ReadResponse is the parsed result of a ReadResponse (ReportDataMessage) IM
// message for a single requested attribute path.
// 10.7.9. ReportDataMessage.
type ReadResponse struct {
	// Status is set when the device returned an AttributeStatusIB for the
	// requested path (i.e. an error) instead of attribute data.
	Status *InvokeStatus
	// Value holds the decoded AttributeDataIB's Data element when the
	// device returned attribute data successfully. Nil when Status is set.
	Value tlv.Element
}
