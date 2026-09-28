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

// Package device is the device side of go-matter: the pieces a Matter node
// needs to be commissioned, as opposed to commissioning others.
//
// It is at an early stage. A Device listens on UDP, advertises itself as a
// commissionable node (_matterc._udp) with the go-mdns responder, answers
// PASE with a provisioned verifier, and answers CASE on the fabrics it has
// joined. On each session it serves the Interaction Model with the General
// Commissioning cluster, whose fail-safe guards the commissioning changes
// with a DeviceStore transaction, and the Operational Credentials cluster:
// the device attests with the credentials of an AttestationProvider,
// generates its operational key for CSRRequest, and joins the fabric
// AddTrustedRootCertificate and AddNOC install. The commissioner then
// completes commissioning over CASE on the new fabric, which commits it.
//
// Nothing here is Matter certified. A product built on this package needs
// its own vendor ID, device attestation credentials and certification.
package device
