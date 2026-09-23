// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

/*
Package matter implements a Matter commissioner.

# Status

The package is a commissioner (controller). It discovers a commissionable
device over BLE and mDNS, commissions it onto a fabric, and reads, writes and
invokes the clusters of the node afterwards. Running as a Matter device is not
implemented: go-matter cannot be commissioned by another controller, and it
serves no cluster of its own.

The device attestation chain of trust is not validated. The attestation
exchange runs and its response is parsed, but the certificate chain is accepted
without being verified against the Distributed Compliance Ledger, so this
package does not reject an untrusted device. There are no Interaction Model
subscriptions either: an attribute is read on demand.

# Commissioning

A commissioner is started once, and it then discovers, commissions and reaches
the devices of its fabric.

	commissioner := matter.NewCommissioner()
	if err := commissioner.Start(); err != nil {
		return err
	}
	defer commissioner.Stop()

	payload, err := encoding.NewPairingCodeFromString(code)
	if err != nil {
		return err
	}

	commissionee, err := commissioner.Commission(ctx, payload)

[Commissioner.Commission] bounds the whole PASE-through-CASE exchange with
[DefaultCommissioningTimeout], because a device commits its new fabric to
persistent storage and then re-advertises itself over mDNS before CASE can
start, which a short deadline expires in the middle of.

# Operating a node

A commissioned node is kept in the store of the commissioner, so it is reached
again without being commissioned a second time.

	node, err := commissioner.Connect(ctx, nodeID)
	if err != nil {
		return err
	}

	res, err := node.ReadAttribute(endpointID, clusterID, attributeID)

Every reconnect is a full CASE handshake: this package holds no session
resumption.

The cluster packages under matter/cluster wrap the attributes and the commands
of a cluster, so that an identifier does not have to be written out by hand.
*/
package matter
