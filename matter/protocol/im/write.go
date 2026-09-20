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

// WriteResponse is the parsed result of a WriteResponse IM message for a
// single written attribute path.
// 10.7.5. WriteResponseMessage.
type WriteResponse struct {
	// Status is the AttributeStatusIB's StatusIB for the written path.
	// Zero value (IMStatus=0, ClusterStatus=0) means success.
	Status InvokeStatus
}

// IsSuccess returns true when the write completed without error.
func (r *WriteResponse) IsSuccess() bool {
	return r.Status.IMStatus == 0 && r.Status.ClusterStatus == 0
}
