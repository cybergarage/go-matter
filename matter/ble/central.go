// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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
// See the License for the specific

package ble

// Central represents a Bluetooth central device.
type Central interface {
	Scanner
}

type central struct {
	Scanner
}

// NewCentral creates a new Bluetooth central device.
func NewCentral() Central {
	return &central{
		Scanner: NewScanner(),
	}
}
