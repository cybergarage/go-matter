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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := scanner.Scan(ctx)
	if err != nil {
		log.Errorf("Failed to scan: %v", err)
	}

	log.Infof("Discovered matter devices:")
	for n, dev := range scanner.Devices() {
		log.Infof("[%d] %s", n, dev.String())
		if !dev.IsCommissionable() {
			continue
		}
		if err := dev.Connect(context.Background()); err != nil {
			log.Errorf("Failed to connect: %v", err)
			continue
		}
		service, ok := dev.LookupService(ble.MatterServiceUUID)
		if ok {
			log.Infof("Lookup service: %s", service.String())
		} else {
			log.Errorf("Failed to lookup service: %s", ble.MatterServiceUUID)
		}
		defer func() {
			if err := dev.Disconnect(); err != nil {
				log.Errorf("Failed to disconnect: %v", err)
			}
		}()
		notify := func(char ble.Characteristic, data []byte) {
			log.Infof("Notify data: % X", data)
		}
		c2, ok := service.LookupCharacteristic(ble.C2)
		if !ok {
			log.Errorf("Failed to lookup characteristic C2: %v", err)
			continue
		}
		err := c2.Notify(notify)
		if err != nil {
			log.Errorf("Failed to enable notify: %v", err)
			continue
		}
	}
}
