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

import (
	"slices"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// The global attributes every cluster has (Matter Core 7.13), which the
// Server reports from what is registered.
const (
	GeneratedCommandListAttributeID AttributeID = 0xFFF8
	AcceptedCommandListAttributeID  AttributeID = 0xFFF9
	AttributeListAttributeID        AttributeID = 0xFFFB
)

// ensureGlobalAttributesLocked registers the global list attributes of a
// cluster the first time something of it is registered.
func (s *Server) ensureGlobalAttributesLocked(endpoint EndpointID, cluster ClusterID) {
	for _, id := range []AttributeID{GeneratedCommandListAttributeID, AcceptedCommandListAttributeID, AttributeListAttributeID} {
		path := AttributePath{Endpoint: endpoint, Cluster: cluster, Attribute: id}
		if _, ok := s.attributes[path]; ok {
			continue
		}
		s.attributes[path] = attributeEntry{
			handler: func(_ *AttributeRequest, enc tlv.Encoder, tag tlv.Tag) Status {
				return encodeIDList(enc, tag, s.globalList(endpoint, cluster, id))
			},
			privilege: DefaultReadPrivilege,
		}
	}
}

// globalList returns the IDs a global list attribute reports: the
// accepted commands, the response commands they generate, or the
// attributes of a cluster, sorted.
func (s *Server) globalList(endpoint EndpointID, cluster ClusterID, id AttributeID) []uint32 {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	var ids []uint32
	switch id {
	case AttributeListAttributeID:
		for p := range s.attributes {
			if p.Endpoint == endpoint && p.Cluster == cluster {
				ids = append(ids, uint32(p.Attribute))
			}
		}
	case AcceptedCommandListAttributeID, GeneratedCommandListAttributeID:
		for p, e := range s.commands {
			if p.endpoint != endpoint || p.cluster != cluster {
				continue
			}
			if id == AcceptedCommandListAttributeID {
				ids = append(ids, uint32(p.command))
				continue
			}
			for _, g := range e.generated {
				if !slices.Contains(ids, uint32(g)) {
					ids = append(ids, uint32(g))
				}
			}
		}
	}
	slices.Sort(ids)
	return ids
}

func encodeIDList(enc tlv.Encoder, tag tlv.Tag, ids []uint32) Status {
	enc.BeginArray(tag)
	for _, id := range ids {
		if err := enc.PutUnsigned(tlv.NewAnonymousTag(), uint64(id)); err != nil {
			return StatusFailure
		}
	}
	if err := enc.EndContainer(); err != nil {
		return StatusFailure
	}
	return StatusSuccess
}

// Endpoints returns the endpoints something is registered on, sorted.
func (s *Server) Endpoints() []EndpointID {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	var endpoints []EndpointID
	for p := range s.attributes {
		if !slices.Contains(endpoints, p.Endpoint) {
			endpoints = append(endpoints, p.Endpoint)
		}
	}
	for p := range s.commands {
		if !slices.Contains(endpoints, p.endpoint) {
			endpoints = append(endpoints, p.endpoint)
		}
	}
	slices.Sort(endpoints)
	return endpoints
}

// Clusters returns the server clusters registered on an endpoint, sorted,
// as a Descriptor's ServerList reports them.
func (s *Server) Clusters(endpoint EndpointID) []ClusterID {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	var clusters []ClusterID
	for p := range s.attributes {
		if p.Endpoint == endpoint && !slices.Contains(clusters, p.Cluster) {
			clusters = append(clusters, p.Cluster)
		}
	}
	for p := range s.commands {
		if p.endpoint == endpoint && !slices.Contains(clusters, p.cluster) {
			clusters = append(clusters, p.cluster)
		}
	}
	slices.Sort(clusters)
	return clusters
}
