// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package device

import (
	"errors"
	"sync"

	"github.com/cybergarage/go-mdns/mdns"
)

// MDNSAdvertiser is the Advertiser which publishes a device's services with
// the go-mdns responder. It starts its mdns.Server when it first publishes,
// and stops it on Withdraw.
type MDNSAdvertiser struct {
	mutex   sync.Mutex
	server  *mdns.Server
	owned   bool
	started bool
	current *mdns.LocalService
	// operational are the published operational services, by full name.
	operational map[string]*mdns.LocalService
}

// NewMDNSAdvertiser returns an MDNSAdvertiser with a server of its own.
func NewMDNSAdvertiser() *MDNSAdvertiser {
	return &MDNSAdvertiser{
		mutex:   sync.Mutex{},
		server:  mdns.NewServer(),
		owned:   true,
		started: false,
		current: nil,

		operational: map[string]*mdns.LocalService{},
	}
}

// NewMDNSAdvertiserWithServer returns an MDNSAdvertiser which publishes
// through server, such as one the application also publishes other
// services with. The caller starts and stops server.
func NewMDNSAdvertiserWithServer(server *mdns.Server) *MDNSAdvertiser {
	return &MDNSAdvertiser{
		mutex:   sync.Mutex{},
		server:  server,
		owned:   false,
		started: true,
		current: nil,

		operational: map[string]*mdns.LocalService{},
	}
}

// commissionableLocalService maps a CommissionableService to the service
// the responder publishes.
func commissionableLocalService(svc CommissionableService) *mdns.LocalService {
	return &mdns.LocalService{
		Instance:  svc.InstanceName,
		Service:   CommissionableServiceType,
		Domain:    ServiceDomain,
		Subtypes:  svc.Subtypes(),
		Host:      svc.Hostname,
		Port:      svc.Port,
		TXT:       svc.TXT(),
		Addresses: nil,
	}
}

// AdvertiseCommissionable implements Advertiser.
func (a *MDNSAdvertiser) AdvertiseCommissionable(svc CommissionableService) error {
	if err := svc.Validate(); err != nil {
		return err
	}
	local := commissionableLocalService(svc)

	a.mutex.Lock()
	defer a.mutex.Unlock()
	if err := a.startLocked(); err != nil {
		return err
	}
	// A new instance name is a new service: withdraw the previous one, as
	// a device does when it reopens its commissioning window.
	if a.current != nil && a.current.FullName() != local.FullName() {
		if err := a.server.Deregister(a.current); err != nil {
			return err
		}
	}
	if err := a.server.Register(local); err != nil {
		return err
	}
	a.current = local
	return nil
}

// WithdrawCommissionable implements Advertiser. It sends goodbye records
// for the commissionable service, and keeps the server running for the
// operational services.
func (a *MDNSAdvertiser) WithdrawCommissionable() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.current == nil {
		return nil
	}
	err := a.server.Deregister(a.current)
	a.current = nil
	return err
}

func (a *MDNSAdvertiser) startLocked() error {
	if a.started {
		return nil
	}
	if err := a.server.Start(); err != nil {
		return err
	}
	a.started = true
	return nil
}

// operationalLocalService maps an OperationalService to the service the
// responder publishes.
func operationalLocalService(svc OperationalService) *mdns.LocalService {
	return &mdns.LocalService{
		Instance:  svc.InstanceName(),
		Service:   OperationalServiceType,
		Domain:    ServiceDomain,
		Subtypes:  svc.Subtypes(),
		Host:      svc.Hostname,
		Port:      svc.Port,
		TXT:       svc.TXT(),
		Addresses: nil,
	}
}

// AdvertiseOperational implements Advertiser.
func (a *MDNSAdvertiser) AdvertiseOperational(svcs []OperationalService) error {
	locals := make(map[string]*mdns.LocalService, len(svcs))
	for _, svc := range svcs {
		if err := svc.Validate(); err != nil {
			return err
		}
		local := operationalLocalService(svc)
		locals[local.FullName()] = local
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()
	var errs []error
	for name, published := range a.operational {
		if _, keep := locals[name]; keep {
			continue
		}
		if err := a.server.Deregister(published); err != nil {
			errs = append(errs, err)
		}
		delete(a.operational, name)
	}
	if len(locals) == 0 {
		return errors.Join(errs...)
	}
	if err := a.startLocked(); err != nil {
		return errors.Join(append(errs, err)...)
	}
	for name, local := range locals {
		if _, published := a.operational[name]; published {
			continue
		}
		if err := a.server.Register(local); err != nil {
			errs = append(errs, err)
			continue
		}
		a.operational[name] = local
	}
	return errors.Join(errs...)
}

// Withdraw implements Advertiser. It sends goodbye records for the
// published services and stops the server the advertiser owns.
func (a *MDNSAdvertiser) Withdraw() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	var errs []error
	if a.current != nil {
		if err := a.server.Deregister(a.current); err != nil {
			errs = append(errs, err)
		}
		a.current = nil
	}
	for name, published := range a.operational {
		if err := a.server.Deregister(published); err != nil {
			errs = append(errs, err)
		}
		delete(a.operational, name)
	}
	if a.owned && a.started {
		if err := a.server.Stop(); err != nil {
			errs = append(errs, err)
		}
		a.started = false
	}
	return errors.Join(errs...)
}
