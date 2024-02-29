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
	_ "embed"

	"github.com/cybergarage/go-mdns/mdns"
	"github.com/cybergarage/go-mdns/mdns/protocol"
)

// Commissionee represents a commissionee.
type Commissionee struct {
	*mdns.Service
}

// NewCommissioneeWithMessage returns a new commissionee with a mDNS message.
func NewCommissioneeWithMessage(msg *protocol.Message) (*Commissionee, error) {
	service, err := mdns.NewServiceWithMessage(msg)
	if err != nil {
		return nil, err
	}
	return NewCommissioneeWithService(service), nil
}

// NewCommissioneeWithService returns a new commissionee with a mDNS service.
func NewCommissioneeWithService(service *mdns.Service) *Commissionee {
	com := &Commissionee{
		Service: service,
	}
	return com
}

func (com *Commissionee) lookupAttribute(name string) (string, bool) {
	attr, ok := com.LookupAttribute(name)
	if !ok {
		return "", false
	}
	return attr.Value(), true
}

// LookupDiscriminator returns a discriminator.
func (com *Commissionee) LookupDiscriminator() (string, bool) {
	return com.lookupAttribute(TxtRecordDiscriminator)
}
