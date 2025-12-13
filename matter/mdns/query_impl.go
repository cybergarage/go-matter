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
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-mdns/mdns"
	"github.com/cybergarage/go-mdns/mdns/dns"
)

// OnboardingPayload defines the common onboarding payload fields.
type OnboardingPayload = encoding.OnboardingPayload

type query struct {
	subtype string
	service string
	domain  string
}

// QueryOption represents an option for configuring a Query.
type QueryOption func(*query)

// WithQuerySubtype sets the subtype for the query.
func WithQuerySubtype(subtype string) QueryOption {
	return func(q *query) {
		q.subtype = subtype
	}
}

// WithQueryService sets the service for the query.
func WithQueryService(service string) QueryOption {
	return func(q *query) {
		q.service = service
	}
}

// WithQueryOnboardingPayload sets the onboarding payload for the query.
func WithQueryOnboardingPayload(payload OnboardingPayload) QueryOption {
	return func(q *query) {
		switch {
		case payload.Discriminator().IsShort():
			q.subtype = fmt.Sprintf("%s%d",
				QuerySubtypeShortDiscriminator,
				payload.Discriminator().Short(),
			)
		default:
			q.subtype = fmt.Sprintf("%s%d",
				QuerySubtypeLongDiscriminator,
				payload.Discriminator().Full(),
			)
		}
	}
}

// NewQuery creates a new Query instance.
func NewQuery(opts ...QueryOption) Query {
	q := &query{
		subtype: "",
		service: "",
		domain:  mdns.LocalDomain,
	}
	for _, opt := range opts {
		opt(q)
	}
	return q
}

// Subtype returns the subtype for the query.
func (q *query) Subtype() string {
	return q.subtype
}

// Service returns the service name for the query.
func (q *query) Service() string {
	return q.service
}

// DomainName returns the domain name for the query.
func (q *query) DomainName() string {
	labels := []string{}
	if 0 < len(q.subtype) {
		labels = append(labels, q.subtype, mdns.Subtype)
	}
	labels = append(labels, q.service, q.domain)
	return dns.NewNameWithStrings(labels...)
}

// String returns the string representation of the query.
func (q *query) String() string {
	return q.DomainName()
}
