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
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	mdnspkg "github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// recordProgress returns a context which records the progress reported in
// it, and the record.
func recordProgress() (context.Context, *[]CommissioningProgress) {
	var got []CommissioningProgress
	ctx := contextWithCommissioningProgress(context.Background(), []CommissionOption{
		"another option",
		WithCommissioningProgress(func(p CommissioningProgress) { got = append(got, p) }),
	})
	return ctx, &got
}

func TestCommissioningProgressContext(t *testing.T) {
	ctx, got := recordProgress()
	reportCommissioningProgress(ctx, CommissioningStagePASE, 0, "")
	reportCommissioningProgress(ctx, CommissioningStageCASE, 2, "192.168.100.62")
	want := []CommissioningProgress{
		{Stage: CommissioningStagePASE, Attempt: 1},
		{Stage: CommissioningStageCASE, Attempt: 2, Detail: "192.168.100.62"},
	}
	if fmt.Sprint(*got) != fmt.Sprint(want) {
		t.Fatalf("progress = %v, want %v", *got, want)
	}

	// The last progress option wins, as with the other options.
	var first, last int
	ctx = contextWithCommissioningProgress(context.Background(), []CommissionOption{
		WithCommissioningProgress(func(CommissioningProgress) { first++ }),
		WithCommissioningProgress(func(CommissioningProgress) { last++ }),
	})
	reportCommissioningProgress(ctx, CommissioningStagePASE, 1, "")
	if first != 0 || last != 1 {
		t.Fatalf("first = %d, last = %d; want the last option told", first, last)
	}

	// Without a progress option, nothing is reported, and nothing fails.
	plain := contextWithCommissioningProgress(context.Background(), nil)
	reportCommissioningProgress(plain, CommissioningStagePASE, 1, "")

	// A device takes the option without complaint.
	dev := &baseDevice{}
	if err := dev.parseCommissionOptions(WithCommissioningProgress(func(CommissioningProgress) {})); err != nil {
		t.Fatalf("parseCommissionOptions() = %v", err)
	}
}

// Each discovery round, operational discovery and CASE attempt is
// reported, with the addresses CASE tries.
func TestCommissioningProgressOfRepeatedStages(t *testing.T) {
	ctx, got := recordProgress()
	payload := testPairingCode(t)
	rounds := 0
	_, err := discoverMatching(ctx, payload, 10*time.Millisecond, time.Second, func(context.Context) ([]CommissionableDevice, error) {
		rounds++
		return []CommissionableDevice{&stubCommissionableDevice{match: rounds == 2}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	stale := &stubOperationalNode{port: 5540, addrs: []net.IP{net.ParseIP("192.168.1.80")}}
	fresh := &stubOperationalNode{port: 5540, addrs: []net.IP{net.ParseIP("192.168.100.62"), net.ParseIP("fe80::1")}}
	discoveries := 0
	stubOperationalCASE(t, func(context.Context) (mdnspkg.CommissionableNode, error) {
		discoveries++
		if discoveries == 1 {
			return stale, nil
		}
		return fresh, nil
	}, func(_ context.Context, node mdnspkg.CommissionableNode) (session.SecureSession, error) {
		if node == stale {
			return nil, timeoutError{}
		}
		return nil, errors.New("established")
	})
	_, _ = reachOperationalNode(ctx, &stubDiscoverer{}, operationalCASEPeer{}, nil, nil)

	want := []CommissioningProgress{
		{Stage: CommissioningStageDiscovering, Attempt: 1},
		{Stage: CommissioningStageDiscovering, Attempt: 2},
		{Stage: CommissioningStageOperationalDiscovery, Attempt: 1},
		{Stage: CommissioningStageCASE, Attempt: 1, Detail: "192.168.1.80"},
		{Stage: CommissioningStageOperationalDiscovery, Attempt: 2},
		{Stage: CommissioningStageCASE, Attempt: 2, Detail: "192.168.100.62, fe80::1"},
	}
	if fmt.Sprint(*got) != fmt.Sprint(want) {
		t.Fatalf("progress =\n%v\nwant\n%v", *got, want)
	}
}
