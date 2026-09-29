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
	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
)

// checkAccess is the device's Access Control (Matter Core 6.6): it grants
// a request when the Access Control List of the session's fabric has an
// entry for the session's subject, the requested endpoint and cluster, and
// a privilege which grants the required one.
//
// A PASE session is granted Administer implicitly: it only exists while
// the commissioning window is open, for the commissioner (6.6.2.9).
func (d *Device) checkAccess(req im.AccessRequest) bool {
	info := d.lookupSession(req.Session)
	if !info.known {
		return false
	}
	if !info.isCASE {
		return true
	}
	entries, err := d.opCreds.aclEntries(info.fabricIndex)
	if err != nil {
		log.Errorf("device: load the ACL of fabric %d: %v", info.fabricIndex, err)
		return false
	}
	for _, entry := range entries {
		if entry.AuthMode != store.AuthModeCASE {
			continue
		}
		if !im.Privilege(entry.Privilege).Grants(req.Privilege) {
			continue
		}
		if !subjectMatches(entry.Subjects, info.peerNodeID, info.peerCATs) {
			continue
		}
		if !targetMatches(entry.Targets, req.Endpoint, req.Cluster) {
			continue
		}
		return true
	}
	return false
}

// subjectMatches reports whether a CASE subject, its node ID and CATs, is
// one of an entry's subjects; no subjects match every subject (6.6.5.2).
// A CAT subject matches a CAT with the same identifier and at least its
// version.
func subjectMatches(subjects []uint64, nodeID uint64, cats []uint32) bool {
	if len(subjects) == 0 {
		return true
	}
	for _, subject := range subjects {
		switch {
		case credentials.IsOperationalNodeID(subject):
			if subject == nodeID {
				return true
			}
		case credentials.IsCASEAuthenticatedTag(subject):
			want := uint32(subject)
			for _, cat := range cats {
				if cat>>16 == want>>16 && want&0xFFFF <= cat&0xFFFF {
					return true
				}
			}
		}
	}
	return false
}

// targetMatches reports whether an endpoint and cluster are one of an
// entry's targets; no targets match every one (6.6.5.3). A target naming a
// device type never matches, since the device does not describe its
// endpoints yet.
func targetMatches(targets []store.ACLTarget, endpoint im.EndpointID, cluster im.ClusterID) bool {
	if len(targets) == 0 {
		return true
	}
	for _, target := range targets {
		if target.DeviceType != nil {
			continue
		}
		if target.Cluster != nil && im.ClusterID(*target.Cluster) != cluster {
			continue
		}
		if target.Endpoint != nil && im.EndpointID(*target.Endpoint) != endpoint {
			continue
		}
		return true
	}
	return false
}
