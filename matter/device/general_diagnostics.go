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
	"bytes"
	"crypto/subtle"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
)

// General Diagnostics cluster (Matter Core 11.12).
const (
	GeneralDiagnosticsClusterID im.ClusterID = 0x0033

	networkInterfacesAttributeID        im.AttributeID = 0x0000
	rebootCountAttributeID              im.AttributeID = 0x0001
	upTimeAttributeID                   im.AttributeID = 0x0002
	testEventTriggersEnabledAttributeID im.AttributeID = 0x0008

	testEventTriggerCommandID     im.CommandID = 0x00
	timeSnapshotCommandID         im.CommandID = 0x01
	timeSnapshotResponseCommandID im.CommandID = 0x02

	generalDiagnosticsClusterRevision = 2

	// rebootCounterName is the persistent counter of the device's boots.
	rebootCounterName = "boot"
	// testEventEnableKeyLength is the length of the EnableKey of a
	// TestEventTrigger (11.12.7.1).
	testEventEnableKeyLength = 16
)

// InterfaceType is the InterfaceTypeEnum of a network interface
// (11.12.5.3).
type InterfaceType uint8

const (
	InterfaceTypeUnspecified InterfaceType = 0
	InterfaceTypeWiFi        InterfaceType = 1
	InterfaceTypeEthernet    InterfaceType = 2
	InterfaceTypeCellular    InterfaceType = 3
	InterfaceTypeThread      InterfaceType = 4
)

// errInvalidTestEventKey is returned by WithTestEventTriggers for a key
// which is not 16 bytes, or is all zeros, which disables the triggers.
var errInvalidTestEventKey = errors.New("device: a test event enable key is 16 bytes, not all zero")

// TestEventTriggerHandler runs the test event trigger an authorized
// TestEventTrigger command asks for, and returns false for a trigger it
// does not know (11.12.7.1).
type TestEventTriggerHandler func(trigger uint64) bool

// WithTestEventTriggers enables the TestEventTrigger command with enableKey,
// the 16-byte key a test harness must present, calling handler for each
// trigger. Test event triggers are for certification testing; a product
// leaves them disabled.
func WithTestEventTriggers(enableKey []byte, handler TestEventTriggerHandler) Option {
	return func(d *Device) error {
		if len(enableKey) != testEventEnableKeyLength || bytes.Equal(enableKey, make([]byte, testEventEnableKeyLength)) {
			return errInvalidTestEventKey
		}
		d.diagnostics.testEventKey = append([]byte(nil), enableKey...)
		d.diagnostics.testEventHandler = handler
		return nil
	}
}

// generalDiagnostics is the server of the General Diagnostics cluster: the
// node's network interfaces, how often it booted and for how long it has
// been up, and the test event triggers.
type generalDiagnostics struct {
	mutex            sync.Mutex
	now              func() time.Time
	bootTime         time.Time
	rebootCount      uint16
	testEventKey     []byte
	testEventHandler TestEventTriggerHandler
	interfaces       func() ([]net.Interface, error)
}

func newGeneralDiagnostics(now func() time.Time) *generalDiagnostics {
	return &generalDiagnostics{
		mutex:            sync.Mutex{},
		now:              now,
		bootTime:         now(),
		rebootCount:      0,
		testEventKey:     nil,
		testEventHandler: nil,
		interfaces:       net.Interfaces,
	}
}

// boot counts a boot of the device in s, and restarts the up time.
func (gd *generalDiagnostics) boot(s store.DeviceStore) {
	count := uint32(0)
	if counter, err := s.Counter(rebootCounterName, 1, 1); err != nil {
		log.Errorf("device: open the boot counter: %v", err)
	} else if count, err = counter.Next(); err != nil {
		log.Errorf("device: count the boot: %v", err)
	}
	gd.mutex.Lock()
	defer gd.mutex.Unlock()
	gd.bootTime = gd.now()
	gd.rebootCount = uint16(min(count, 0xFFFF)) // nolint: gosec // bounded above
}

func (gd *generalDiagnostics) upTime() time.Duration {
	gd.mutex.Lock()
	defer gd.mutex.Unlock()
	return gd.now().Sub(gd.bootTime)
}

func (gd *generalDiagnostics) register(srv *im.Server) {
	srv.HandleAttribute(rootEndpoint, GeneralDiagnosticsClusterID, networkInterfacesAttributeID, gd.readNetworkInterfaces)
	srv.HandleAttribute(rootEndpoint, GeneralDiagnosticsClusterID, rebootCountAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		gd.mutex.Lock()
		defer gd.mutex.Unlock()
		enc.PutUnsigned2(tag, gd.rebootCount)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, GeneralDiagnosticsClusterID, upTimeAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned8(tag, uint64(gd.upTime()/time.Second)) // nolint: gosec // never negative
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, GeneralDiagnosticsClusterID, testEventTriggersEnabledAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutBool(tag, gd.testEventKey != nil)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, GeneralDiagnosticsClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, 0)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, GeneralDiagnosticsClusterID, clusterRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, generalDiagnosticsClusterRevision)
		return im.StatusSuccess
	})
	srv.HandleCommand(rootEndpoint, GeneralDiagnosticsClusterID, testEventTriggerCommandID, gd.testEventTrigger, im.WithPrivilege(im.PrivilegeManage))
	srv.HandleCommand(rootEndpoint, GeneralDiagnosticsClusterID, timeSnapshotCommandID, gd.timeSnapshot, im.WithResponseCommand(timeSnapshotResponseCommandID))
}

// readNetworkInterfaces reports the interfaces which carry Matter traffic,
// those with a hardware address other than the loopback (11.12.5.2).
func (gd *generalDiagnostics) readNetworkInterfaces(enc tlv.Encoder, tag tlv.Tag) im.Status {
	ifis, err := gd.interfaces()
	if err != nil {
		return im.StatusFailure
	}
	enc.BeginArray(tag)
	for _, ifi := range ifis {
		if ifi.Flags&net.FlagLoopback != 0 || (len(ifi.HardwareAddr) != 6 && len(ifi.HardwareAddr) != 8) {
			continue
		}
		if err := encodeNetworkInterface(enc, ifi); err != nil {
			return im.StatusFailure
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.StatusFailure
	}
	return im.StatusSuccess
}

func encodeNetworkInterface(enc tlv.Encoder, ifi net.Interface) error {
	var v4, v6 [][]byte
	if addrs, err := ifi.Addrs(); err == nil {
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ip := ipnet.IP.To4(); ip != nil {
				v4 = append(v4, ip)
			} else if ip := ipnet.IP.To16(); ip != nil {
				v6 = append(v6, ip)
			}
		}
	}
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutUTF8(tlv.NewContextTag(0), ifi.Name); err != nil {
		return err
	}
	enc.PutBool(tlv.NewContextTag(1), ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagRunning != 0)
	enc.PutNull(tlv.NewContextTag(2)) // OffPremiseServicesReachableIPv4: unknown
	enc.PutNull(tlv.NewContextTag(3)) // OffPremiseServicesReachableIPv6: unknown
	if err := enc.PutOctet(tlv.NewContextTag(4), ifi.HardwareAddr); err != nil {
		return err
	}
	for i, ips := range [][][]byte{v4, v6} {
		enc.BeginArray(tlv.NewContextTag(uint8(5 + i))) // nolint: gosec // 5 or 6
		for _, ip := range ips {
			if err := enc.PutOctet(tlv.NewAnonymousTag(), ip); err != nil {
				return err
			}
		}
		if err := enc.EndContainer(); err != nil {
			return err
		}
	}
	enc.PutUnsigned1(tlv.NewContextTag(7), uint8(interfaceType(ifi.Name)))
	return enc.EndContainer()
}

// interfaceType guesses the type of an interface from its name, as the
// operating system gives no portable way to tell.
func interfaceType(name string) InterfaceType {
	switch {
	case strings.HasPrefix(name, "wl"), strings.HasPrefix(name, "wifi"):
		return InterfaceTypeWiFi
	case strings.HasPrefix(name, "eth"), strings.HasPrefix(name, "en"):
		return InterfaceTypeEthernet
	default:
		return InterfaceTypeUnspecified
	}
}

// testEventTrigger runs a test event trigger when the EnableKey matches the
// device's (11.12.7.1).
func (gd *generalDiagnostics) testEventTrigger(req *im.CommandRequest) im.CommandResult {
	keyField, ok1 := req.Field(0)
	triggerField, ok2 := req.Field(1)
	if !ok1 || !ok2 {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	key, ok := keyField.Bytes()
	trigger, ok3 := triggerField.Unsigned()
	if !ok || !ok3 {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	if len(key) != testEventEnableKeyLength {
		return im.CommandStatus(im.StatusConstraintError)
	}
	if gd.testEventKey == nil || subtle.ConstantTimeCompare(key, gd.testEventKey) != 1 {
		return im.CommandStatus(im.StatusUnsupportedAccess)
	}
	if gd.testEventHandler == nil || !gd.testEventHandler(trigger) {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	return im.CommandStatus(im.StatusSuccess)
}

// timeSnapshot answers with the time since boot and the POSIX time
// (11.12.7.2).
func (gd *generalDiagnostics) timeSnapshot(*im.CommandRequest) im.CommandResult {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned8(tlv.NewContextTag(0), uint64(gd.upTime()/time.Millisecond)) // nolint: gosec // never negative
	enc.PutUnsigned8(tlv.NewContextTag(1), uint64(gd.now().UnixMilli()))         // nolint: gosec // after 1970
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(timeSnapshotResponseCommandID, enc.Bytes())
}
