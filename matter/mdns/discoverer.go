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

package mdns

import (
	"context"
	"time"

	"github.com/cybergarage/go-mdns/mdns"
)

const (
	SDServerType  = "_matter._tcp"
	SearchDomain  = "local."
	SearchTimeout = time.Duration(5 * time.Second)
)

// Discoverer represents a discoverer for commisionners.
type Discoverer interface {
	// Search searches commisioners.
	// 5.4.3.3. Using Existing IP-bearing Network
	// To discover a commissionable device over an existing IP-bearing network connection,
	// the Commis­ sioner SHALL perform service discovery using DNS-SD as detailed in
	// Section 4.3, “Discovery”, and more specifically in Section 4.3.1, “Commissionable Node Discovery”.
	Search(ctx context.Context) ([]mdns.Service, error)
	// Start starts this discoverer.
	Start() error
	// Stop stops this discoverer.
	Stop() error
}
