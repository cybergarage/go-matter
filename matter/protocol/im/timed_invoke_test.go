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

import "testing"

func TestTimedInvoke(t *testing.T) {
	srv := testServer()
	var timed []bool
	srv.HandleCommand(0, 0x003C, 0x02, func(req *CommandRequest) CommandResult {
		timed = append(timed, req.Timed)
		if !req.Timed {
			return CommandStatus(StatusNeedsTimedInteraction)
		}
		return CommandStatus(StatusSuccess)
	})
	client := startServer(t, srv)

	resp, err := Invoke(client, 0, 0x003C, 0x02, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.IMStatus != uint8(StatusNeedsTimedInteraction) {
		t.Fatalf("an untimed invoke: status %+v, want NeedsTimedInteraction", resp.Status)
	}
	resp, err = TimedInvoke(client, 0, 0x003C, 0x02, nil, 0)
	if err != nil || !resp.IsSuccess() {
		t.Fatalf("TimedInvoke() = (%+v, %v)", resp, err)
	}
	if len(timed) != 2 || timed[0] || !timed[1] {
		t.Fatalf("the handler saw timed %v, want [false true]", timed)
	}
}
