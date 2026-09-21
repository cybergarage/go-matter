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

// Package generaldiagnostics provides a client for the Matter General Diagnostics cluster (0x0033).
// Reference: Matter Core Spec 1.5, Section 11.13.
package generaldiagnostics

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// ClusterID is the General Diagnostics cluster identifier.
// 11.13. General Diagnostics Cluster.
const ClusterID im.ClusterID = 0x0033

// Attribute IDs for the General Diagnostics cluster.
// 11.13.6. Attributes. NetworkInterfaces is attribute 0x0000 (a list, not
// modeled by this package); RebootCount is 0x0001 — confirmed against
// connectedhomeip's general-diagnostics-cluster.xml after an earlier
// off-by-one here (0x0000) silently read NetworkInterfaces instead, which
// happened to decode as null against one real device and hard-failed
// ("attribute-report-IBs is not a list") against a second, exposing the
// mistake.
const (
	// RebootCountAttributeID reports the number of times the device has rebooted.
	RebootCountAttributeID im.AttributeID = 0x0001
)

// RebootCount reads the RebootCount attribute of the given endpoint.
// RebootCount is nullable (11.13.6): ok is false, with a nil error, when
// the device reports it as null (e.g. it doesn't track reboot count)
// rather than as an unsigned integer.
func RebootCount(sess session.SecureSession, endpointID im.EndpointID) (uint16, bool, error) {
	resp, err := im.ReadAttribute(sess, endpointID, ClusterID, RebootCountAttributeID)
	if err != nil {
		return 0, false, fmt.Errorf("generaldiagnostics: RebootCount: %w", err)
	}
	if resp.Status != nil {
		return 0, false, fmt.Errorf("generaldiagnostics: RebootCount failed: IM status 0x%02X, cluster status 0x%02X",
			resp.Status.IMStatus, resp.Status.ClusterStatus)
	}
	if resp.Value == nil {
		return 0, false, fmt.Errorf("generaldiagnostics: RebootCount: ReadResponse missing attribute value")
	}
	if resp.Value.Type().IsNull() {
		return 0, false, nil
	}
	v, valueOK := resp.Value.Unsigned2()
	if !valueOK {
		return 0, false, fmt.Errorf("generaldiagnostics: RebootCount: attribute value is not a UINT16")
	}
	return v, true, nil
}
