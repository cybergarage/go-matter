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
)

// CommissioningStage is a stage of a commissioning, in the order of the
// commissioning flow. 5.5. Commissioning Flows.
type CommissioningStage string

const (
	// CommissioningStageDiscovering: the commissioner looks for the
	// device of the onboarding payload over BLE and mDNS, round after
	// round (5.4.3. Discovery by Commissioner).
	CommissioningStageDiscovering CommissioningStage = "discovering"
	// CommissioningStageConnecting: it connects to the device found.
	CommissioningStageConnecting CommissioningStage = "connecting"
	// CommissioningStagePASE: it establishes the PASE session with the
	// passcode (4.14.1. Passcode-Authenticated Session Establishment).
	CommissioningStagePASE CommissioningStage = "pase"
	// CommissioningStageAttestation: it arms the fail-safe and checks the
	// attestation of the device (6.2. Device Attestation).
	CommissioningStageAttestation CommissioningStage = "attestation"
	// CommissioningStageCredentials: it installs the trusted root and the
	// operational certificate of its fabric (11.18.6. Operational
	// Credentials).
	CommissioningStageCredentials CommissioningStage = "credentials"
	// CommissioningStageNetwork: it gives the device its operational
	// network and has it join (11.8. Network Commissioning).
	CommissioningStageNetwork CommissioningStage = "network"
	// CommissioningStageOperationalDiscovery: it looks for the device on
	// its operational network (4.3.2. Operational Discovery).
	CommissioningStageOperationalDiscovery CommissioningStage = "operationalDiscovery"
	// CommissioningStageCASE: it establishes a CASE session with the
	// device (4.14.2. Certificate Authenticated Session Establishment).
	CommissioningStageCASE CommissioningStage = "case"
	// CommissioningStageComplete: it sends CommissioningComplete
	// (11.10.7.6).
	CommissioningStageComplete CommissioningStage = "complete"
)

// CommissioningProgress tells that a commissioning has reached a stage.
type CommissioningProgress struct {
	// Stage is the stage reached.
	Stage CommissioningStage
	// Attempt counts the attempts of a stage which is repeated: the rounds
	// of discovery, and the attempts of operational discovery and CASE.
	// It is 1 for the others.
	Attempt int
	// Detail describes what the stage works with, such as the device
	// found or the address tried; empty when there is nothing to tell. It
	// holds no secret: no passcode, no network credentials.
	Detail string
}

// CommissioningProgressFunc is told the progress of a commissioning, from
// the goroutine which runs it; it is to return quickly.
type CommissioningProgressFunc func(CommissioningProgress)

// WithCommissioningProgress returns a commission option which tells fn
// each stage the commissioning reaches.
func WithCommissioningProgress(fn CommissioningProgressFunc) CommissionOption {
	return progressOption(fn)
}

type commissioningProgressKey struct{}

// contextWithCommissioningProgress returns ctx carrying the progress
// function of opts, the last one as with the other options, or ctx itself
// when opts give none.
func contextWithCommissioningProgress(ctx context.Context, opts []CommissionOption) context.Context {
	var last CommissioningProgressFunc
	for _, opt := range opts {
		if fn, ok := opt.(progressOption); ok && fn != nil {
			last = CommissioningProgressFunc(fn)
		}
	}
	if last == nil {
		return ctx
	}
	return context.WithValue(ctx, commissioningProgressKey{}, last)
}

// reportCommissioningProgress tells the progress function ctx carries, if
// any, that the commissioning has reached stage.
func reportCommissioningProgress(ctx context.Context, stage CommissioningStage, attempt int, detail string) {
	if ctx == nil {
		return
	}
	fn, ok := ctx.Value(commissioningProgressKey{}).(CommissioningProgressFunc)
	if !ok {
		return
	}
	if attempt < 1 {
		attempt = 1
	}
	fn(CommissioningProgress{Stage: stage, Attempt: attempt, Detail: detail})
}
