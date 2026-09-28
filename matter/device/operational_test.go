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
	"reflect"
	"testing"
)

func testOperationalService() OperationalService {
	return OperationalService{
		CompressedFabricID:     0x87E1B004E235A130,
		NodeID:                 0x8FC7772401CD0696,
		Hostname:               "B75AFB458ECD6D6F",
		Port:                   5540,
		SessionIdleInterval:    500,
		SessionActiveInterval:  0,
		SessionActiveThreshold: 0,
	}
}

func TestOperationalServiceNames(t *testing.T) {
	svc := testOperationalService()
	if err := svc.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	if got, want := svc.InstanceFullName(), "87E1B004E235A130-8FC7772401CD0696._matter._tcp.local"; got != want {
		t.Errorf("InstanceFullName() = %q, want %q", got, want)
	}
	if got, want := svc.Subtypes(), []string{"_I87E1B004E235A130"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Subtypes() = %v, want %v", got, want)
	}
	if got, want := svc.TXT(), []string{"SII=500"}; !reflect.DeepEqual(got, want) {
		t.Errorf("TXT() = %v, want %v", got, want)
	}

	local := operationalLocalService(svc)
	if local.FullName() != svc.InstanceFullName() {
		t.Errorf("FullName() = %q, want %q", local.FullName(), svc.InstanceFullName())
	}
	if err := local.Validate(); err != nil {
		t.Errorf("Validate() = %v", err)
	}

	svc.NodeID = 0
	if err := svc.Validate(); err == nil {
		t.Error("Validate() accepted a service without a node ID")
	}
}
