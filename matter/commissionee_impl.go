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

// commissioneeImpl wraps a Device with the operational identity it was
// assigned during commissioning. It's a package-level type (not the
// function-local anonymous-embedding trick newCommissioneeWithDevice used
// before it) because NodeID()/FabricID() aren't promoted from Device and so
// need real method bodies.
type commissioneeImpl struct {
	Device
	identity CommissionedIdentity
}

func newCommissioneeWithIdentity(dev Device, identity CommissionedIdentity) Commissionee {
	return &commissioneeImpl{
		Device:   dev,
		identity: identity,
	}
}

// NodeID returns the operational node ID this device was assigned during
// commissioning.
func (c *commissioneeImpl) NodeID() (NodeID, bool) {
	return c.identity.NodeID, !c.identity.NodeID.IsUnspecified()
}

// FabricID returns the fabric this device joined during commissioning.
func (c *commissioneeImpl) FabricID() (uint64, bool) {
	return c.identity.FabricID, c.identity.FabricID != 0
}
