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
	"sync"

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

// Search searches commissionable Nodes.
// 4.3. Discovery.
func (disc *discoverer) Search(ctx context.Context, query Query) ([]CommissionableNode, error) {
	service := query.Service()
	if len(service) == 0 {
		service = CommissionableNodeService
	}
	dnsQuery := mdns.NewQuery(
		mdns.WithQuerySubtype(query.Subtype()),
		mdns.WithQueryService(service),
		mdns.WithQueryType(query.Type()),
	)

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, SearchTimeout)
		defer cancel()
	}

	services, err := disc.Client.Query(ctx, dnsQuery)
	if err != nil {
		return []CommissionableNode{}, err
	}

	nodes := []CommissionableNode{}
	for _, service := range services {
		node := NewCommissioningNodeWithService(service)
		nodes = append(nodes, node)
	}
	return nodes, nil
}

// SearchUntil searches as Search does, but returns as soon as a response
// gives a node accept takes, instead of at the deadline of ctx: a node
// answers in milliseconds, and the queries of a search otherwise last for
// the whole of its timeout. It returns the nodes of the responses up to
// then, the accepted one included.
func (disc *discoverer) SearchUntil(ctx context.Context, query Query, accept func(CommissionableNode) bool) ([]CommissionableNode, error) {
	service := query.Service()
	if len(service) == 0 {
		service = CommissionableNodeService
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, SearchTimeout)
		defer cancel()
	}
	searchCtx, stop := context.WithCancel(ctx)
	defer stop()

	// The handler sees each response before the query keeps it, so the
	// accepted node is kept here too, in case the query returns first.
	var mu sync.Mutex
	var accepted CommissionableNode
	handler := func(msg mdns.Message) {
		if !msg.IsResponse() {
			return
		}
		srv, err := mdns.NewService(mdns.WithServiceMessage(msg))
		if err != nil {
			return
		}
		node := NewCommissioningNodeWithService(srv)
		if !accept(node) {
			return
		}
		mu.Lock()
		if accepted == nil {
			accepted = node
		}
		mu.Unlock()
		stop()
	}
	dnsQuery := mdns.NewQuery(
		mdns.WithQuerySubtype(query.Subtype()),
		mdns.WithQueryService(service),
		mdns.WithQueryType(query.Type()),
		mdns.WithQueryMessageHandler(handler),
	)

	services, err := disc.Client.Query(searchCtx, dnsQuery)
	if err != nil {
		return []CommissionableNode{}, err
	}

	nodes := make([]CommissionableNode, 0, len(services)+1)
	for _, service := range services {
		nodes = append(nodes, NewCommissioningNodeWithService(service))
	}
	mu.Lock()
	defer mu.Unlock()
	if accepted != nil {
		nodes = append(nodes, accepted)
	}
	return nodes, nil
}
