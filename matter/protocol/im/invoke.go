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

// Package im provides the Matter Interaction Model (IM) client primitives.
// It covers InvokeRequest/InvokeResponse as defined in Matter Core Spec
// section 10.7 (Interaction Model Messages).
package im

import "github.com/cybergarage/go-matter/matter/protocol/session"

// SecureSession is the encrypted channel on which IM messages are sent.
type SecureSession = session.SecureSession

// EndpointID identifies an endpoint on a device.
// 9.5. Endpoints.
type EndpointID uint16

// ClusterID identifies a cluster.
// 7.10. Cluster Identifiers.
type ClusterID uint32

// CommandID identifies a command within a cluster.
// 7.13. Command Identifiers.
type CommandID uint32

// InvokeStatus represents the overall status code returned in an InvokeResponse.
// 10.7.17.2. Status IB.
type InvokeStatus struct {
	// ClusterStatus is the cluster-specific status code (0 = success).
	ClusterStatus uint8
	// IMStatus is the Interaction Model protocol status code (0 = Success).
	IMStatus uint8
}

// InvokeResponse is the parsed result of an InvokeResponse IM message.
// 10.7.17. InvokeResponseMessage.
type InvokeResponse struct {
	// Status contains the status codes for the invocation.
	Status InvokeStatus
	// Payload contains any TLV-encoded command response fields, or nil.
	Payload []byte
}

// IsSuccess returns true when the invocation completed without error.
func (r *InvokeResponse) IsSuccess() bool {
	return r.Status.IMStatus == 0 && r.Status.ClusterStatus == 0
}
