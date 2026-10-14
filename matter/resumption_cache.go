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

package matter

import (
	"sync"

	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
)

// resumptionKey names a node on a fabric.
type resumptionKey struct {
	compressedFabricID uint64
	nodeID             uint64
}

// resumptionCache keeps, per node, the state which resumes the last CASE
// session with it (4.14.2.2. Session Resumption). It lives in memory only:
// the state holds the session's shared secret, which is not written to
// disk, so a commissioner which restarts runs a full CASE first. The zero
// value is ready to use.
type resumptionCache struct {
	mutex  sync.Mutex
	states map[resumptionKey]*caseprotocol.ResumptionState
}

// load returns the state to resume the session with the node, or nil.
func (c *resumptionCache) load(key resumptionKey) *caseprotocol.ResumptionState {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.states[key]
}

// save keeps the state of the session just established with the node, or
// forgets the node's when state is nil.
func (c *resumptionCache) save(key resumptionKey, state *caseprotocol.ResumptionState) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if state == nil {
		delete(c.states, key)
		return
	}
	if c.states == nil {
		c.states = map[resumptionKey]*caseprotocol.ResumptionState{}
	}
	c.states[key] = state
}
