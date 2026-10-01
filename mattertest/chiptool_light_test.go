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

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/device"
	"github.com/cybergarage/go-matter/matter/device/cluster"
)

// lightEndpoint is the endpoint of the On/Off Light the tests add.
const lightEndpoint = 1

// addOnOffLight makes the device an On/Off Light on lightEndpoint, as the
// onofflight example does.
func (d *chipToolDevice) addOnOffLight(t *testing.T) *cluster.OnOff {
	t.Helper()
	ep, err := d.dev.AddEndpoint(lightEndpoint, device.OnOffLightDeviceType)
	if err != nil {
		t.Fatal(err)
	}
	identify := cluster.NewIdentify(cluster.IdentifyTypeLightOutput)
	identify.Register(ep)
	light := cluster.NewOnOff()
	light.Register(ep)
	scenes := cluster.NewScenes()
	scenes.AddSceneHandler(cluster.OnOffClusterID, light)
	scenes.Register(ep)
	cluster.NewGroups(cluster.WithGroupsIdentify(identify), cluster.WithGroupsRemovedHandler(scenes.RemoveGroups)).Register(ep)
	return light
}

// TestChipToolOperatesOnOffLight has chip-tool switch an On/Off Light on
// and off, and read it, after commissioning it.
func TestChipToolOperatesOnOffLight(t *testing.T) {
	chipTool := lookupChipTool(t)
	d := startChipToolDevice(t)
	light := d.addOnOffLight(t)
	chipTool.pair(t, d.nodeID, chipToolPasscode, d.discriminator)
	node := nodeArg(d.nodeID)
	ep := "1"

	out, err := chipTool.run(t, "descriptor", "read", "parts-list", node, "0")
	if err != nil || !strings.Contains(out, "PartsList: 1 entries") {
		t.Fatalf("chip-tool descriptor read parts-list: %v", err)
	}
	out, err = chipTool.run(t, "descriptor", "read", "device-type-list", node, ep)
	if err != nil || !strings.Contains(out, "DeviceType: 256") {
		t.Fatalf("chip-tool descriptor read device-type-list: %v", err)
	}

	for _, step := range []struct {
		command string
		want    bool
	}{
		{"on", true},
		{"toggle", false},
		{"toggle", true},
		{"off", false},
	} {
		if _, err := chipTool.run(t, "onoff", step.command, node, ep); err != nil {
			t.Fatalf("chip-tool onoff %s: %v", step.command, err)
		}
		if light.On() != step.want {
			t.Fatalf("after onoff %s the light is on: %v, want %v", step.command, light.On(), step.want)
		}
		out, err := chipTool.run(t, "onoff", "read", "on-off", node, ep)
		if err != nil {
			t.Fatalf("chip-tool onoff read on-off: %v", err)
		}
		want := "OnOff: FALSE"
		if step.want {
			want = "OnOff: TRUE"
		}
		if !strings.Contains(out, want) {
			t.Fatalf("after onoff %s chip-tool did not read %q", step.command, want)
		}
	}

	if _, err := chipTool.run(t, "identify", "identify", "10", node, ep); err != nil {
		t.Fatalf("chip-tool identify identify: %v", err)
	}
	out, err = chipTool.run(t, "identify", "read", "identify-time", node, ep)
	if err != nil || !strings.Contains(out, "IdentifyTime: ") || strings.Contains(out, "IdentifyTime: 0\n") {
		t.Fatalf("chip-tool identify read identify-time: %v", err)
	}
}

// TestChipToolRecallsScene has chip-tool store the light's state as a
// scene, and recall it after the light changed.
func TestChipToolRecallsScene(t *testing.T) {
	chipTool := lookupChipTool(t)
	d := startChipToolDevice(t)
	light := d.addOnOffLight(t)
	chipTool.pair(t, d.nodeID, chipToolPasscode, d.discriminator)
	node := nodeArg(d.nodeID)
	ep := "1"

	light.Set(true)
	if _, err := chipTool.run(t, "scenesmanagement", "store-scene", "0", "1", node, ep); err != nil {
		t.Fatalf("chip-tool scenesmanagement store-scene: %v", err)
	}
	light.Set(false)
	if _, err := chipTool.run(t, "scenesmanagement", "recall-scene", "0", "1", node, ep); err != nil {
		t.Fatalf("chip-tool scenesmanagement recall-scene: %v", err)
	}
	if !light.On() {
		t.Fatal("recalling the scene did not turn the light back on")
	}
	out, err := chipTool.run(t, "scenesmanagement", "read", "fabric-scene-info", node, ep)
	if err != nil || !strings.Contains(out, "SceneCount: 1") {
		t.Fatalf("chip-tool scenesmanagement read fabric-scene-info: %v", err)
	}
}

// TestChipToolAddsLightToGroup has chip-tool write a group key set and
// map a group to it with Group Key Management, and put the light in the
// group with the Groups cluster.
func TestChipToolAddsLightToGroup(t *testing.T) {
	chipTool := lookupChipTool(t)
	d := startChipToolDevice(t)
	d.addOnOffLight(t)
	chipTool.pair(t, d.nodeID, chipToolPasscode, d.discriminator)
	node := nodeArg(d.nodeID)

	keySet := `{"groupKeySetID": 42, "groupKeySecurityPolicy": 0, "epochKey0": "hex:d0d1d2d3d4d5d6d7d8d9dadbdcdddedf", "epochStartTime0": 2220000,` +
		` "epochKey1": null, "epochStartTime1": null, "epochKey2": null, "epochStartTime2": null}`
	if _, err := chipTool.run(t, "groupkeymanagement", "key-set-write", keySet, node, "0"); err != nil {
		t.Fatalf("chip-tool groupkeymanagement key-set-write: %v", err)
	}
	if _, err := chipTool.run(t, "groupkeymanagement", "write", "group-key-map", `[{"groupId": 257, "groupKeySetID": 42, "fabricIndex": 1}]`, node, "0"); err != nil {
		t.Fatalf("chip-tool groupkeymanagement write group-key-map: %v", err)
	}
	out, err := chipTool.run(t, "groups", "add-group", "257", "Kitchen", node, "1")
	if err != nil || !strings.Contains(out, "status: 0") {
		t.Fatalf("chip-tool groups add-group: %v", err)
	}
	out, err = chipTool.run(t, "groupkeymanagement", "read", "group-table", node, "0")
	if err != nil || !strings.Contains(out, "GroupId: 257") {
		t.Fatalf("chip-tool groupkeymanagement read group-table: %v", err)
	}
	keys, err := d.store.LoadGroupKeys(1)
	if err != nil || len(keys.Groups) != 1 || keys.Groups[0].Name != "Kitchen" {
		t.Fatalf("the device holds the groups (%+v, %v)", keys.Groups, err)
	}
}

// TestChipToolSubscribesOnOffLight has chip-tool, in interactive mode,
// subscribe to the OnOff attribute of an On/Off Light, and checks the
// reports of the changes the light makes by itself.
func TestChipToolSubscribesOnOffLight(t *testing.T) {
	chipTool := lookupChipTool(t)
	d := startChipToolDevice(t)
	light := d.addOnOffLight(t)
	chipTool.pair(t, d.nodeID, chipToolPasscode, d.discriminator)

	shell := chipTool.interactive(t)
	shell.send(t, "onoff subscribe on-off 0 10 "+nodeArg(d.nodeID)+" 1")
	// The priming report comes before the SubscribeResponse.
	shell.waitFor(t, "OnOff: FALSE")
	shell.waitFor(t, "Subscription established")

	// A wall switch, say, turns the light on and off.
	light.Set(true)
	shell.waitFor(t, "OnOff: TRUE")
	light.Set(false)
	shell.waitFor(t, "OnOff: FALSE")
}

// chipToolShell is chip-tool in interactive mode, which keeps its
// subscriptions between the commands it reads from its input.
type chipToolShell struct {
	stdin io.WriteCloser
	lines chan string
}

// interactive starts chip-tool in interactive mode, logging its output,
// and stops it when the test ends.
func (c *chipTool) interactive(t *testing.T) *chipToolShell {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), chipToolCommandTimeout)
	args := []string{"interactive", "start", "--storage-directory", c.storage}
	t.Logf("$ %s %s", toolChipTool, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, c.path, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	shell := &chipToolShell{stdin: stdin, lines: make(chan string, 8192)}
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(out)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := stripANSI(scanner.Text())
			t.Log(line)
			select {
			case shell.lines <- line:
			default:
			}
		}
		_, _ = io.Copy(io.Discard, out)
	}()
	t.Cleanup(func() {
		_, _ = io.WriteString(stdin, "quit\n")
		_ = stdin.Close()
		done := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cancel()
			<-done
		}
		cancel()
		<-scanned
	})
	return shell
}

// send writes a command line to chip-tool.
func (s *chipToolShell) send(t *testing.T, line string) {
	t.Helper()
	t.Logf(">>> %s", line)
	if _, err := io.WriteString(s.stdin, line+"\n"); err != nil {
		t.Fatalf("chip-tool interactive: %v", err)
	}
}

// waitFor waits for chip-tool to print a line containing substr.
func (s *chipToolShell) waitFor(t *testing.T, substr string) {
	t.Helper()
	timeout := time.After(30 * time.Second)
	for {
		select {
		case line := <-s.lines:
			if strings.Contains(line, substr) {
				return
			}
		case <-timeout:
			t.Fatalf("chip-tool did not print %q", substr)
		}
	}
}
