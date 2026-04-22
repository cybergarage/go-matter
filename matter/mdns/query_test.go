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

package mdns

import "testing"

func TestNewOperationalNodeQueryBrowse(t *testing.T) {
	query := NewOperationalNodeQuery("")

	if got := query.Service(); got != OperationalNodeService {
		t.Fatalf("Service() = %q, want %q", got, OperationalNodeService)
	}
	if got := query.DomainName(); got != "_matter._tcp.local" {
		t.Fatalf("DomainName() = %q, want %q", got, "_matter._tcp.local")
	}
}

func TestNewOperationalNodeQuerySpecificServiceInstance(t *testing.T) {
	query := NewOperationalNodeQuery("1122334455667788")

	if got := query.Service(); got != "1122334455667788."+OperationalNodeService {
		t.Fatalf("Service() = %q, want specific operational service", got)
	}
	if got := query.DomainName(); got != "1122334455667788._matter._tcp.local" {
		t.Fatalf("DomainName() = %q, want %q", got, "1122334455667788._matter._tcp.local")
	}
}
