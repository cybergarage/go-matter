// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/ble"
	"github.com/cybergarage/go-matter/matter/ble/btp"
	"github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/types"
)

type bleDevice struct {
	*baseDevice
	ble.Device
	ble.Service
	transport  ble.Transport
	segmenter  *btp.Segmenter
	discoverer mdns.Discoverer
}

func newBLEDevice(dev ble.Device, srv ble.Service, discoverer mdns.Discoverer) CommissionableDevice {
	return &bleDevice{
		baseDevice: newBaseDevice(),
		Device:     dev,
		Service:    srv,
		transport:  nil,
		discoverer: discoverer,
	}
}

// Type returns the device type.
func (dev *bleDevice) Type() DeviceType {
	return types.BLEDevice
}

// Address returns the device address.
func (dev *bleDevice) Address() string {
	return dev.Device.Address().String()
}

// Transmit writes data to the transport.
func (dev *bleDevice) Transmit(ctx context.Context, b []byte) error {
	if dev.transport == nil || dev.segmenter == nil {
		return fmt.Errorf("transport is not opened")
	}
	// 4.19.4.4. BTP Data Packet Header. Messages larger than the negotiated
	// fragment size must be split into multiple segments written in order.
	for _, seg := range dev.segmenter.EncodeMessage(b) {
		if _, err := dev.transport.Write(ctx, seg); err != nil {
			return err
		}
	}
	return nil
}

// Receive reads data from the transport.
func (dev *bleDevice) Receive(ctx context.Context) ([]byte, error) {
	if dev.transport == nil || dev.segmenter == nil {
		return nil, fmt.Errorf("transport is not opened")
	}
	// A single Matter message may be split across multiple BTP segments;
	// keep feeding received segments to the reassembler until it reports a
	// complete message.
	for {
		segBytes, err := dev.transport.Read(ctx)
		if err != nil {
			return nil, err
		}
		msg, ok, err := dev.segmenter.Feed(segBytes)
		if err != nil {
			return nil, err
		}
		if ok {
			return msg, nil
		}
	}
}

// Commission commissions the node with the given commissioning options.
func (dev *bleDevice) Commission(ctx context.Context, payload OnboardingPayload, opts ...CommissionOption) (CommissionedIdentity, error) {
	log.Infof("Connected to device: %s", dev.String())

	if err := dev.parseCommissionOptions(opts...); err != nil {
		log.Errorf("Failed to parse commission options for device (%s): %v", dev.String(), err)
		return CommissionedIdentity{}, err
	}

	if err := dev.Connect(ctx); err != nil {
		log.Errorf("Failed to connect to device (%s): %v", dev.String(), err)
		return CommissionedIdentity{}, err
	}
	defer func() {
		if err := dev.Disconnect(); err != nil {
			log.Errorf("Failed to disconnect: %v", err)
		}
	}()

	// The service captured during discovery only reflects the advertisement
	// data (no characteristics). Now that the device is connected, look it
	// up again so the underlying ble.Device performs real GATT discovery
	// and populates the characteristics (C1/C2) needed by Service.Open.
	srv, ok := dev.Device.LookupService(ble.MatterServiceUUID)
	if !ok {
		err := fmt.Errorf("service (%s) not found after connect", ble.MatterServiceUUID.String())
		log.Errorf("Failed to look up device service (%s): %v", dev.String(), err)
		return CommissionedIdentity{}, err
	}
	dev.Service = srv

	log.Infof("Device service: %s", dev.Service.String())

	var err error
	dev.transport, err = dev.Service.Open()
	if err != nil {
		log.Errorf("Failed to open device transport (%s): %v", dev.String(), err)
		return CommissionedIdentity{}, err
	}
	defer func() {
		if err := dev.transport.Close(); err != nil {
			log.Error(err)
		}
		dev.transport = nil
	}()

	res, err := dev.transport.Handshake(ctx)
	if err != nil {
		log.Errorf("Failed to perform handshake with device (%s): %v", dev.String(), err)
		return CommissionedIdentity{}, err
	}

	log.Infof("Handshake response: %s", res.String())
	dev.segmenter = btp.NewSegmenter(res.FragmentSize())

	paseClient := pase.NewInitiator(dev, payload.Passcode())
	sessionKeys, err := paseClient.EstablishSession(ctx)
	if err != nil {
		log.Errorf("Failed to establish PASE session with device (%s): %v", dev.String(), err)
		return CommissionedIdentity{}, err
	}

	sess := session.NewSecureSession(dev, sessionKeys)
	operationalCfg, _ := dev.OperationalCredentialsConfig()
	wifiCfg, _ := dev.WiFiNetworkConfig()
	adminCfg, _ := dev.AdministratorConfig()
	identity, err := commissionWithSession(ctx, sess, dev.discoverer, operationalCfg, wifiCfg, adminCfg, true)
	if err != nil {
		log.Errorf("Commissioning failed for device (%s): %v", dev.String(), err)
		return CommissionedIdentity{}, err
	}

	fabricID, _ := adminCfg.FabricID()
	return CommissionedIdentity{
		NodeID:   NodeID(identity.nodeID),
		FabricID: fabricID,
		NOC:      identity.noc,
		ICAC:     identity.icac,
	}, nil
}

// MatchesOnboardingPayload checks whether the device matches the given onboarding payload.
func (dev *bleDevice) MatchesOnboardingPayload(payload OnboardingPayload) bool {
	return dev.matchesOnboardingPayload(dev, payload)
}

// String returns the string representation of the BLE device.
func (dev *bleDevice) String() string {
	return dev.baseDevice.string(dev)
}

// MarshalObject returns an object suitable for marshaling to JSON.
func (dev *bleDevice) MarshalObject() any {
	return dev.baseDevice.marshalObject(dev)
}
