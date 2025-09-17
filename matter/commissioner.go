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
	"errors"
	"fmt"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/ble"
	"github.com/cybergarage/go-matter/matter/encoding"
)

const (
	// DefaultCommissioningTimeout is the default commissioning timeout.
	DefaultCommissioningTimeout = time.Duration(5 * time.Second)
)

// CommissioningOptions represents the commissioning options.
type CommissioningOptions interface {
	encoding.OnboardingPayload
}

// commissioner represents a commissioner.
type Commissioner interface {
	// Scannar returns the BLE scanner.
	Scannar() ble.Scanner
	// Commission commissions a device with the given commissioning options.
	Commission(ctx context.Context, options CommissioningOptions) error
	// Start starts the commissioner.
	Start() error
	// Stop stops the commissioner.
	Stop() error
}

// commissioner represents a commissioner.
type commissioner struct {
	ble.Central
	*Discoverer
}

// NewCommissioner returns a new commissioner.
func NewCommissioner() *commissioner {
	com := &commissioner{
		Central:    ble.NewCentral(),
		Discoverer: NewDiscoverer(),
	}
	return com
}

// Scannar returns the BLE scanner.
func (com *commissioner) Scannar() ble.Scanner {
	return com.Central
}

func (com *commissioner) bleCommission(ctx context.Context, options CommissioningOptions) error {
	scanner := com.Scannar()
	err := scanner.Scan(ctx)
	if err != nil {
		return err
	}

	log.Infof("Discovered matter devices:")
	for n, dev := range scanner.DiscoveredDevices() {
		log.Infof("[%d] %s", n, dev.String())
	}

	dev, err := scanner.LookupDeviceByDiscriminator(options.Discriminator())
	if err != nil {
		if errors.Is(err, ble.ErrNotFound) {
			return fmt.Errorf("device not found: %d (%d)", options.Passcode(), uint16(options.Discriminator()))
		} else {
			return fmt.Errorf("failed to lookup device: %d (%d): %w", options.Passcode(), uint16(options.Discriminator()), err)
		}
	}

	log.Infof("Found device: %s", dev.String())

	if !dev.IsCommissionable() {
		return fmt.Errorf("device is not commissionable: %s", dev.String())
	}

	if err := dev.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer func() {
		if err := dev.Disconnect(); err != nil {
			log.Errorf("Failed to disconnect: %v", err)
		}
	}()

	log.Infof("Connected to device: %s", dev.String())

	service, err := dev.Service()
	if err != nil {
		return fmt.Errorf("failed to get device service: %s: %w", dev.String(), err)
	}

	log.Infof("Device service: %s", service.String())

	transport, err := service.Open()
	if err != nil {
		return fmt.Errorf("failed to open device transport: %s: %w", dev.String(), err)
	}
	defer transport.Close()

	res, err := transport.Handshake()
	if err != nil {
		return fmt.Errorf("failed to perform handshake: %s: %w", dev.String(), err)
	}

	log.Infof("Handshake response: %s", res.String())

	return nil
}

// Commission commissions a device with the given commissioning options.
func (com *commissioner) Commission(ctx context.Context, options CommissioningOptions) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultCommissioningTimeout)
		defer cancel()
	}
	err := com.bleCommission(ctx, options)
	if err != nil {
		return err
	}
	return nil
}

// Start starts the commissioner.
func (com *commissioner) Start() error {
	err := com.Discoverer.Start()
	if err != nil {
		return err
	}

	return nil
}

// Stop stops the commissioner.
func (com *commissioner) Stop() error {
	err := com.Discoverer.Stop()
	if err != nil {
		return err
	}

	return nil
}
