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

package ble

import (
	"context"
	_ "embed"
	"testing"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/ble"
)

func TestScanner(t *testing.T) {
	log.EnableStdoutDebug(true)

	scanner := ble.NewScanner()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := scanner.Scan(ctx)
	if err != nil {
		log.Errorf("Failed to scan: %v", err)
	}

	log.Infof("Discovered matter devices:")
	for n, dev := range scanner.DiscoveredDevices() {
		log.Infof("[%d] %s", n, dev.String())
		if !dev.IsCommissionable() {
			continue
		}
		if err := dev.Connect(context.Background()); err != nil {
			log.Errorf("Failed to connect: %v", err)
			continue
		}
		defer func() {
			if err := dev.Disconnect(); err != nil {
				log.Errorf("Failed to disconnect: %v", err)
			}
		}()
		service, err := dev.Service()
		if err != nil {
			log.Errorf("Failed to get service: %v", err)
			continue
		}
		transport, err := service.Open()
		if err != nil {
			log.Errorf("Failed to open service: %v", err)
			continue
		}
		defer func() {
			if err := transport.Close(); err != nil {
				log.Errorf("Failed to close transport: %v", err)
			}
		}()
		err = transport.Handshake()
		if err != nil {
			log.Errorf("Failed to handshake: %v", err)
		}
	}
}
