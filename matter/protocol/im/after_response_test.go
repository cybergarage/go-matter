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
	"testing"
	"time"
)

// TestServerAfterResponse checks that a command's AfterResponse runs once
// its response has been sent.
func TestServerAfterResponse(t *testing.T) {
	srv := testServer()
	done := make(chan struct{})
	srv.HandleCommand(0, 0x003E, 0x0A, func(*CommandRequest) CommandResult {
		result := CommandStatus(StatusSuccess)
		result.AfterResponse = func() { close(done) }
		return result
	})
	client := startServer(t, srv)
	resp, err := Invoke(client, 0, 0x003E, 0x0A, nil)
	if err != nil || !resp.IsSuccess() {
		t.Fatalf("Invoke() = (%+v, %v)", resp, err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("AfterResponse was not called")
	}
}
