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

package device

import (
	"fmt"
	"strconv"

	"github.com/cybergarage/go-matter/matter/mdns"
)

// OperationalServiceType is the DNS-SD service of an operational node
// (Matter Core 4.3.2). It is "_tcp" whatever transport the node uses.
const OperationalServiceType = mdns.OperationalNodeService

// OperationalService describes the _matter._tcp service a device
// advertises for each fabric it has joined (Matter Core 4.3.2), by which
// the fabric's nodes find it for CASE. Like CommissionableService it is
// backend-neutral.
type OperationalService struct {
	// CompressedFabricID and NodeID name the instance, as
	// "<CompressedFabricID>-<NodeID>" in 16 uppercase hex digits each.
	CompressedFabricID uint64
	NodeID             uint64
	// Hostname is the target host's name without the domain, shared with
	// the commissionable service.
	Hostname string
	// Port is the UDP port the device receives Matter messages on.
	Port int
	// SessionIdleInterval, SessionActiveInterval and
	// SessionActiveThreshold are the MRP parameters in milliseconds
	// (4.3.4); 0 omits them and the defaults apply.
	SessionIdleInterval    uint32
	SessionActiveInterval  uint32
	SessionActiveThreshold uint16
}

// Validate reports whether s can be advertised.
func (s OperationalService) Validate() error {
	if s.NodeID == 0 {
		return fmt.Errorf("device: operational service without a node ID")
	}
	if !mdns.HostnameRegexp.MatchString(s.Hostname) {
		return fmt.Errorf("device: host name %q is not 16 uppercase hex digits", s.Hostname)
	}
	if s.Port <= 0 || s.Port > 0xFFFF {
		return fmt.Errorf("device: port %d out of range", s.Port)
	}
	if s.SessionIdleInterval > MaxSessionInterval || s.SessionActiveInterval > MaxSessionInterval {
		return fmt.Errorf("device: session interval exceeds %d ms", MaxSessionInterval)
	}
	return nil
}

// InstanceName returns the DNS-SD instance name, such as
// "2906C908D115D362-00000000DEADBEEF" (4.3.2.1).
func (s OperationalService) InstanceName() string {
	return fmt.Sprintf("%016X-%016X", s.CompressedFabricID, s.NodeID)
}

// ServiceName returns the fully qualified service type,
// "_matter._tcp.local".
func (s OperationalService) ServiceName() string {
	return OperationalServiceType + "." + ServiceDomain
}

// InstanceFullName returns the fully qualified instance name.
func (s OperationalService) InstanceFullName() string {
	return s.InstanceName() + "." + s.ServiceName()
}

// Subtypes returns the compressed fabric ID subtype label, such as
// "_I2906C908D115D362" (4.3.2.2).
func (s OperationalService) Subtypes() []string {
	return []string{fmt.Sprintf("_I%016X", s.CompressedFabricID)}
}

// TXT returns the TXT record entries (4.3.4), which may be none.
func (s OperationalService) TXT() []string {
	var txt []string
	if s.SessionIdleInterval != 0 {
		txt = append(txt, txtEntry(TxtRecordSessionIdleInterval, strconv.FormatUint(uint64(s.SessionIdleInterval), 10)))
	}
	if s.SessionActiveInterval != 0 {
		txt = append(txt, txtEntry(TxtRecordSessionActiveInterval, strconv.FormatUint(uint64(s.SessionActiveInterval), 10)))
	}
	if s.SessionActiveThreshold != 0 {
		txt = append(txt, txtEntry(TxtRecordSessionActiveThreshold, strconv.Itoa(int(s.SessionActiveThreshold))))
	}
	return txt
}
