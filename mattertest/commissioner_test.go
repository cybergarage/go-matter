// Copyright (C) 2022 The go-matter Authors All rights reserved.
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
	_ "embed"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/encoding"
)

func TestCommissioner(t *testing.T) {
	tests := []struct {
		paringCode string
	}{
		// {
		// 	paringCode: "3035-750-7966", // BLE
		// },
		// {
		// 	paringCode: "3572-993-5174", // BLE
		// },
		{
			paringCode: "2167-692-8175", // IP
		},
	}

	cmr := matter.NewCommissioner()
	err := cmr.Start()
	if err != nil {
		t.Errorf("Failed to start commissioner: %v", err)
		return
	}

	defer func() {
		err := cmr.Stop()
		if err != nil {
			t.Errorf("Failed to stop commissioner: %v", err)
		}
	}()

	for _, tt := range tests {
		t.Run(tt.paringCode, func(t *testing.T) {
			paringCode, err := encoding.NewPairingCodeFromString(tt.paringCode)
			if err != nil {
				t.Errorf("Failed to decode pairing code %q: %v", tt.paringCode, err)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(5)*time.Second)
			defer cancel()

			cme, err := cmr.Commission(ctx, paringCode)
			if err != nil {
				t.Skipf("Failed to commission device: %v", err)
				return
			}

			t.Logf("Successfully commissioned device: %s", cme.String())
		})
	}
}
