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

package mattertest

// The tests in this file commission a matter/device Device with chip-tool,
// the controller of the Matter SDK (project-chip/connectedhomeip), when it
// is installed, to check the device against the reference implementation.
// chip-tool is found as $CHIP_TOOL, or as chip-tool on the PATH, such as
// the chip-tool snap on Linux; on Linux it discovers devices through
// avahi-daemon. A test is skipped when chip-tool is not installed, and with
// -short.
//
// GO_MATTER_TEST_REQUIRE lists the tools which must be available, such as
// "chip-tool". A listed tool which is missing fails its tests instead of
// skipping them, so that a CI job which installs it cannot pass without
// running it. The output of chip-tool is logged, so a verbose log shows
// what it did.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/credentials/testcreds"
	"github.com/cybergarage/go-matter/matter/device"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-matter/matter/store"
	"github.com/cybergarage/go-matter/matter/types"
)

const (
	toolChipTool   = "chip-tool"
	chipToolEnv    = "CHIP_TOOL"
	requireToolEnv = "GO_MATTER_TEST_REQUIRE"

	// chipToolPasscode is the SDK's default test passcode, which chip-tool
	// accepts; it rejects trivial ones such as 12345678.
	chipToolPasscode = 20202021
	// chipToolCommandTimeout bounds one chip-tool command. Pairing
	// includes discovery and the operational discovery after AddNOC.
	chipToolCommandTimeout = 2 * time.Minute
)

// isToolRequired reports whether GO_MATTER_TEST_REQUIRE lists tool.
func isToolRequired(tool string) bool {
	for name := range strings.SplitSeq(os.Getenv(requireToolEnv), ",") {
		if strings.TrimSpace(name) == tool {
			return true
		}
	}
	return false
}

// chipTool is chip-tool with a storage directory of its own.
type chipTool struct {
	path    string
	storage string
}

// lookupChipTool returns chip-tool, skipping the test when it is not
// installed, or failing it when GO_MATTER_TEST_REQUIRE lists it.
func lookupChipTool(t *testing.T) *chipTool {
	t.Helper()
	if testing.Short() {
		t.Skip("the chip-tool tests use the network; skipped with -short")
	}
	name := os.Getenv(chipToolEnv)
	if name == "" {
		name = toolChipTool
	}
	path, err := exec.LookPath(name)
	if err != nil {
		if isToolRequired(toolChipTool) {
			t.Fatalf("chip-tool is required by %s: %s is not installed", requireToolEnv, name)
		}
		t.Skipf("%s is not installed", name)
	}
	t.Logf("running %s (%s)", toolChipTool, path)
	return &chipTool{path: path, storage: chipToolStorage(t, path)}
}

// chipToolStorage returns a new, empty storage directory for chip-tool, so
// that it starts without fabrics and does not touch the user's. A snap can
// only write its own directories, so a snap's is made in the snap's user
// data directory.
func chipToolStorage(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}
	if !strings.Contains(path, "/snap/") && !strings.Contains(resolved, "/snap/") {
		return t.TempDir()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	common := filepath.Join(home, "snap", toolChipTool, "common")
	if err := os.MkdirAll(common, 0o755); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(common, "go-matter-test-") //nolint:usetesting // t.TempDir cannot be made where the snap can write
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// run runs chip-tool with args and its storage directory, logging its
// output line by line, and returns the output.
func (c *chipTool) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), chipToolCommandTimeout)
	defer cancel()
	args = append(args, "--storage-directory", c.storage)
	t.Logf("$ %s %s", toolChipTool, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, c.path, args...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return "", err
	}
	var output strings.Builder
	scanner := bufio.NewScanner(out)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := stripANSI(scanner.Text())
		output.WriteString(line)
		output.WriteByte('\n')
		t.Log(line)
	}
	_, _ = io.Copy(io.Discard, out)
	err = cmd.Wait()
	if ctx.Err() != nil {
		err = fmt.Errorf("chip-tool timed out after %v: %w", chipToolCommandTimeout, ctx.Err())
	}
	return output.String(), err
}

// stripANSI removes the color escape sequences chip-tool logs with.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || 0x7e < s[j]) {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func randomUint16(t *testing.T) uint16 {
	t.Helper()
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return binary.BigEndian.Uint16(b)
}

// chipToolDevice is a device started for chip-tool to commission, and
// the node ID chip-tool gives it.
type chipToolDevice struct {
	dev           *device.Device
	store         store.DeviceStore
	discriminator uint16
	nodeID        uint64
}

// startChipToolDevice starts a device with the SDK's test attestation
// credentials. A random discriminator and node ID keep the test apart from
// other devices, and from earlier runs, on the network.
func startChipToolDevice(t *testing.T) *chipToolDevice {
	t.Helper()
	d := &chipToolDevice{
		dev:           nil,
		store:         store.NewMemDeviceStore(),
		discriminator: randomUint16(t) & device.MaxDiscriminator,
		nodeID:        uint64(0x10000 + uint32(randomUint16(t))),
	}
	d.start(t, ":0")
	t.Logf("device: discriminator %d, port %d, node ID 0x%X", d.discriminator, d.dev.CommissionableService().Port, d.nodeID)
	return d
}

// start starts a device on d's store, listening on addr.
func (d *chipToolDevice) start(t *testing.T, addr string) {
	t.Helper()
	attestation, err := testcreds.AttestationProvider()
	if err != nil {
		t.Fatal(err)
	}
	dev, err := device.New(
		device.WithDeviceStore(d.store),
		device.WithPasscode(types.Passcode(chipToolPasscode)),
		device.WithAddress(addr),
		device.WithDiscriminator(d.discriminator),
		device.WithVendorID(testcreds.VendorID),
		device.WithProductID(testcreds.ProductID),
		device.WithDeviceName("go-matter test device"),
		device.WithAttestationProvider(attestation),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := dev.Start(); err != nil {
		if isToolRequired(toolChipTool) {
			t.Fatalf("the device cannot advertise here: %v", err)
		}
		t.Skipf("the device cannot advertise here: %v", err)
	}
	d.dev = dev
	t.Cleanup(func() {
		if err := dev.Stop(); err != nil {
			t.Errorf("Device.Stop() error = %v", err)
		}
	})
}

// restart stops the device and starts it again on the same store and
// port, as a device rebooting does. The caller adds its endpoints again.
func (d *chipToolDevice) restart(t *testing.T) {
	t.Helper()
	port := d.dev.CommissionableService().Port
	if err := d.dev.Stop(); err != nil {
		t.Fatalf("Device.Stop() error = %v", err)
	}
	d.start(t, fmt.Sprintf(":%d", port))
}

func nodeArg(nodeID uint64) string {
	return fmt.Sprintf("0x%X", nodeID)
}

// pair has chip-tool commission the device by its long discriminator:
// discovery, PASE, attestation against the SDK's test trust store, AddNOC,
// operational discovery, CASE and CommissioningComplete.
func (c *chipTool) pair(t *testing.T, nodeID uint64, passcode uint32, discriminator uint16, extra ...string) {
	t.Helper()
	args := append([]string{"pairing", "onnetwork-long", nodeArg(nodeID), fmt.Sprint(passcode), fmt.Sprint(discriminator)}, extra...)
	if _, err := c.run(t, args...); err != nil {
		t.Fatalf("chip-tool pairing: %v", err)
	}
}

// checkFabrics checks the fabrics the device has committed.
func (d *chipToolDevice) checkFabrics(t *testing.T, nodeIDs ...uint64) {
	t.Helper()
	fabrics, err := d.store.ListDeviceFabrics()
	if err != nil || len(fabrics) != len(nodeIDs) {
		t.Fatalf("the device holds (%d fabrics, %v), want %d", len(fabrics), err, len(nodeIDs))
	}
	for i, f := range fabrics {
		if f.NodeID != nodeIDs[i] {
			t.Fatalf("the device joined fabric %d as node 0x%X, want 0x%X", f.FabricIndex, f.NodeID, nodeIDs[i])
		}
	}
	if d.dev.IsCommissioningWindowOpen() {
		t.Fatal("the commissioning window is still open after chip-tool paired the device")
	}
}

// TestChipToolCommissionsDevice commissions a matter/device Device with
// chip-tool over the network, then reads an attribute over the CASE
// session chip-tool establishes with the commissioned device.
func TestChipToolCommissionsDevice(t *testing.T) {
	chipTool := lookupChipTool(t)
	d := startChipToolDevice(t)

	chipTool.pair(t, d.nodeID, chipToolPasscode, d.discriminator)
	d.checkFabrics(t, d.nodeID)

	// A new CASE session, found by the operational service.
	out, err := chipTool.run(t, "generalcommissioning", "read", "breadcrumb", nodeArg(d.nodeID), "0")
	if err != nil {
		t.Fatalf("chip-tool generalcommissioning read breadcrumb: %v", err)
	}
	if !strings.Contains(out, "Breadcrumb: 0") {
		t.Fatal("chip-tool did not report the Breadcrumb")
	}

	// The General Diagnostics of the root node.
	out, err = chipTool.run(t, "generaldiagnostics", "read", "reboot-count", nodeArg(d.nodeID), "0")
	if err != nil || !strings.Contains(out, "RebootCount: 1") {
		t.Fatalf("chip-tool generaldiagnostics read reboot-count: %v", err)
	}
	out, err = chipTool.run(t, "generaldiagnostics", "time-snapshot", nodeArg(d.nodeID), "0")
	if err != nil || !strings.Contains(strings.ToLower(out), "systemtimems") {
		t.Fatalf("chip-tool generaldiagnostics time-snapshot: %v", err)
	}
}

// chipToolNodeID is the node ID chip-tool commissions as by default, the
// subject of the Administer entry AddNOC grants it.
const chipToolNodeID = 112233

// TestChipToolWritesACL has chip-tool read the ACL AddNOC made, and write
// one with a second entry, which the SDK writes as an empty list followed
// by the entries appended one by one.
func TestChipToolWritesACL(t *testing.T) {
	chipTool := lookupChipTool(t)
	d := startChipToolDevice(t)
	chipTool.pair(t, d.nodeID, chipToolPasscode, d.discriminator)

	out, err := chipTool.run(t, "accesscontrol", "read", "acl", nodeArg(d.nodeID), "0")
	if err != nil {
		t.Fatalf("chip-tool accesscontrol read acl: %v", err)
	}
	if !strings.Contains(out, "Privilege: 5") || !strings.Contains(out, fmt.Sprint(chipToolNodeID)) {
		t.Fatal("chip-tool did not read the Administer entry of its node")
	}

	acl := fmt.Sprintf(`[{"fabricIndex": 1, "privilege": 5, "authMode": 2, "subjects": [%d], "targets": null},`+
		` {"fabricIndex": 1, "privilege": 1, "authMode": 2, "subjects": [4660], "targets": [{"cluster": 40, "endpoint": 0, "deviceType": null}]}]`, chipToolNodeID)
	if _, err := chipTool.run(t, "accesscontrol", "write", "acl", acl, nodeArg(d.nodeID), "0"); err != nil {
		t.Fatalf("chip-tool accesscontrol write acl: %v", err)
	}
	entries, err := d.store.LoadACL(1)
	if err != nil || len(entries) != 2 {
		t.Fatalf("the device holds the ACL (%+v, %v), want 2 entries", entries, err)
	}
	if e := entries[1]; e.Privilege != store.PrivilegeView || len(e.Subjects) != 1 || e.Subjects[0] != 4660 ||
		len(e.Targets) != 1 || e.Targets[0].Cluster == nil || *e.Targets[0].Cluster != 40 {
		t.Fatalf("the second entry is %+v", e)
	}
	out, err = chipTool.run(t, "accesscontrol", "read", "acl", nodeArg(d.nodeID), "0")
	if err != nil || !strings.Contains(out, "ACL: 2 entries") {
		t.Fatalf("chip-tool did not read back 2 entries: %v", err)
	}
}

// manualPairingCodeRegexp finds the manual pairing code chip-tool prints
// for a commissioning window it opened.
var manualPairingCodeRegexp = regexp.MustCompile(`Manual pairing code: \[(\d{11}|\d{21})\]`)

// TestChipToolOpensCommissioningWindow has chip-tool, as the first
// fabric's administrator, open an enhanced commissioning window on the
// commissioned device with the Administrator Commissioning cluster, and a
// second chip-tool commissioner join a second fabric through it with the
// one-time passcode.
func TestChipToolOpensCommissioningWindow(t *testing.T) {
	chipTool := lookupChipTool(t)
	d := startChipToolDevice(t)
	chipTool.pair(t, d.nodeID, chipToolPasscode, d.discriminator)
	d.checkFabrics(t, d.nodeID)

	// option 1 is the enhanced commissioning method: chip-tool generates
	// the verifier of a one-time passcode for the window.
	windowDiscriminator := (d.discriminator + 1) & device.MaxDiscriminator
	out, err := chipTool.run(t, "pairing", "open-commissioning-window", nodeArg(d.nodeID), "1", "180", "1000", fmt.Sprint(windowDiscriminator))
	if err != nil {
		t.Fatalf("chip-tool pairing open-commissioning-window: %v", err)
	}
	if !d.dev.IsCommissioningWindowOpen() {
		t.Fatal("the commissioning window did not open")
	}
	if svc := d.dev.CommissionableService(); svc.Discriminator != windowDiscriminator || svc.CommissioningMode != mdns.CommissioningModeDynamicPasscode {
		t.Fatalf("the window is advertised with discriminator %d and CM=%v, want %d and CM=2", svc.Discriminator, svc.CommissioningMode, windowDiscriminator)
	}
	m := manualPairingCodeRegexp.FindStringSubmatch(out)
	if m == nil {
		t.Fatal("chip-tool did not print the manual pairing code of the window")
	}
	code, err := encoding.NewPairingCodeFromString(m[1])
	if err != nil {
		t.Fatalf("parse the manual pairing code %s: %v", m[1], err)
	}
	passcode := uint32(code.Passcode())
	if passcode == chipToolPasscode {
		t.Fatal("the enhanced window uses the device's passcode, not a one-time one")
	}

	// A second commissioner joins a second fabric through the window.
	secondNodeID := d.nodeID + 1
	chipTool.pair(t, secondNodeID, passcode, windowDiscriminator, "--commissioner-name", "beta")
	d.checkFabrics(t, d.nodeID, secondNodeID)

	// Both administrators reach the device on their own fabric.
	out, err = chipTool.run(t, "operationalcredentials", "read", "commissioned-fabrics", nodeArg(d.nodeID), "0")
	if err != nil {
		t.Fatalf("chip-tool operationalcredentials read commissioned-fabrics: %v", err)
	}
	if !strings.Contains(out, "CommissionedFabrics: 2") {
		t.Fatal("chip-tool did not report 2 commissioned fabrics")
	}
	out, err = chipTool.run(t, "operationalcredentials", "read", "current-fabric-index", nodeArg(secondNodeID), "0", "--commissioner-name", "beta")
	if err != nil {
		t.Fatalf("chip-tool operationalcredentials read current-fabric-index: %v", err)
	}
	if !strings.Contains(out, "CurrentFabricIndex: 2") {
		t.Fatal("chip-tool did not report the second fabric as the current one")
	}

	// The second administrator labels its fabric, and the first removes
	// it again.
	if _, err := chipTool.run(t, "operationalcredentials", "update-fabric-label", "beta", nodeArg(secondNodeID), "0", "--commissioner-name", "beta"); err != nil {
		t.Fatalf("chip-tool operationalcredentials update-fabric-label: %v", err)
	}
	if fabrics, err := d.store.ListDeviceFabrics(); err != nil || len(fabrics) != 2 || fabrics[1].Label != "beta" {
		t.Fatalf("the device holds (%+v, %v), want the second fabric labelled beta", fabrics, err)
	}
	if _, err := chipTool.run(t, "operationalcredentials", "remove-fabric", "2", nodeArg(d.nodeID), "0"); err != nil {
		t.Fatalf("chip-tool operationalcredentials remove-fabric: %v", err)
	}
	d.checkFabrics(t, d.nodeID)
}
