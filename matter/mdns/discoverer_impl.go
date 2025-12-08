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

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-mdns/mdns"
	"github.com/cybergarage/go-mdns/mdns/dns"
)

// discoverer represents a discoverer for commisionners.
type discoverer struct {
	mdns.Client
}

// NewDiscoverer returns a new discoverer.
func NewDiscoverer() Discoverer {
	disc := &discoverer{
		Client: mdns.NewClient(),
	}
	return disc
}

// MessageReceived is a callback when a message is received.
func (disc *discoverer) MessageReceived(msg dns.Message) {
	log.HexInfo(msg.Bytes())
}

// Start starts this discoverer.
func (disc *discoverer) Start() error {
	return disc.Client.Start()
}

// Stop stops this discoverer.
func (disc *discoverer) Stop() error {
	return disc.Client.Stop()
}

// Search searches commisioners.
// 5.4.3.3. Using Existing IP-bearing Network
// To discover a commissionable device over an existing IP-bearing network connection,
// the Commis­ sioner SHALL perform service discovery using DNS-SD as detailed in
// Section 4.3, “Discovery”, and more specifically in Section 4.3.1, “Commissionable Node Discovery”.
func (disc *discoverer) Search(ctx context.Context) ([]mdns.Service, error) {
	query := mdns.NewQuery(
		mdns.WithQueryServices(SDServerType),
		mdns.WithQueryDomain(SearchDomain),
	)

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, SearchTimeout)
		defer cancel()
	}

	services, err := disc.Client.Query(ctx, query)
	if err != nil {
		return []mdns.Service{}, err
	}

	return services, nil
}
