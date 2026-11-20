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

package mattertest

import (
	"context"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter"
)

// connectNode connects to a commissioned node within timeout, failing the
// test when it cannot, and closes the node when the test ends.
func connectNode(t *testing.T, cmr matter.Commissioner, nodeID matter.NodeID, timeout time.Duration) matter.Node {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	node, err := cmr.Connect(ctx, nodeID)
	if err != nil {
		t.Fatalf("Commissioner.Connect() error = %v", err)
	}
	t.Cleanup(func() {
		if err := node.Close(); err != nil {
			t.Errorf("Node.Close() error = %v", err)
		}
	})
	return node
}
