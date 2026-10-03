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
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-mdns/mdns"
)

const (
	// RegisterTimeout bounds how long the advertiser waits for the
	// responder to probe the names of a service, which normally takes
	// about a second (RFC 6762, 8.1).
	RegisterTimeout = 10 * time.Second
	// MaxInstanceNameAttempts is how many random instance names the
	// advertiser tries for the commissionable service when another node
	// holds the name.
	MaxInstanceNameAttempts = 3
)

// MDNSAdvertiser is the Advertiser which publishes a device's services with
// the go-mdns responder. It starts its mdns.Server when it first publishes,
// and stops it on Withdraw.
//
// The responder probes the names of a service before it publishes it, so
// publishing takes about a second, and it does not rename a service whose
// name another node on the link holds. The advertiser handles the conflicts
// as Matter expects (Core 4.3.1 and 4.3.2): the commissionable service is
// published again with a new random instance name, which is what the name
// is for, while an operational service, named by its fabric and node ID, is
// not renamed; a conflict there means another node uses the same node ID,
// which is reported as an error. A host name conflict is reported as an
// error for both.
type MDNSAdvertiser struct {
	mutex   sync.Mutex
	server  *mdns.Server
	owned   bool
	started bool
	current *mdns.LocalService
	// requested is the instance name the device asked to publish the
	// commissionable service with, and current holds the name it is
	// published with, which differs after a conflict.
	requested string
	renamed   string
	// operational are the published operational services, by full name.
	operational map[string]*mdns.LocalService
}

// NewMDNSAdvertiser returns an MDNSAdvertiser with a server of its own.
func NewMDNSAdvertiser() *MDNSAdvertiser {
	a := newMDNSAdvertiser(nil, true)
	a.server = mdns.NewServer(mdns.WithServerConflictHandler(a.HandleConflict))
	return a
}

// NewMDNSAdvertiserWithServer returns an MDNSAdvertiser which publishes
// through server, such as one the application also publishes other
// services with. The caller starts server before the device publishes, and
// stops it. To have the advertiser handle the conflicts found after a
// service is published, the caller passes HandleConflict to the server:
//
//	var adv *device.MDNSAdvertiser
//	server := mdns.NewServer(mdns.WithServerConflictHandler(func(err *mdns.ConflictError) {
//		adv.HandleConflict(err)
//	}))
//	adv = device.NewMDNSAdvertiserWithServer(server)
func NewMDNSAdvertiserWithServer(server *mdns.Server) *MDNSAdvertiser {
	return newMDNSAdvertiser(server, false)
}

func newMDNSAdvertiser(server *mdns.Server, owned bool) *MDNSAdvertiser {
	return &MDNSAdvertiser{
		mutex:     sync.Mutex{},
		server:    server,
		owned:     owned,
		started:   !owned,
		current:   nil,
		requested: "",
		renamed:   "",

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

// register publishes local, waiting for the responder to probe its names.
func (a *MDNSAdvertiser) register(local *mdns.LocalService) error {
	ctx, cancel := context.WithTimeout(context.Background(), RegisterTimeout)
	defer cancel()
	return a.server.Register(ctx, local)
}

// registerCommissionableLocked publishes local, with a new random instance
// name while another node holds the name.
func (a *MDNSAdvertiser) registerCommissionableLocked(local *mdns.LocalService) error {
	var err error
	for range MaxInstanceNameAttempts {
		err = a.register(local)
		var conflict *mdns.ConflictError
		if !errors.As(err, &conflict) || !conflict.IsInstanceConflict() {
			return err
		}
		renamed := NewInstanceName()
		log.Warnf("device: commissionable instance name %s is used by another node, renamed to %s", local.Instance, renamed)
		local.Instance = renamed
	}
	return fmt.Errorf("device: no unique commissionable instance name in %d attempts: %w", MaxInstanceNameAttempts, err)
}

// AdvertiseCommissionable implements Advertiser. It returns when the
// service is published, after the responder probes its names, and it
// renames the instance when another node holds the name.
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
	// The device publishes the same instance name again, such as after a
	// failed commissioning attempt: keep the name a conflict renamed it to.
	if svc.InstanceName == a.requested && a.renamed != "" {
		local.Instance = a.renamed
	}
	// A new instance name is a new service: withdraw the previous one, as
	// a device does when it reopens its commissioning window.
	if a.current != nil && a.current.FullName() != local.FullName() {
		if err := a.server.Deregister(a.current); err != nil {
			return err
		}
		a.current = nil
	}
	if err := a.registerCommissionableLocked(local); err != nil {
		return err
	}
	a.current = local
	a.requested = svc.InstanceName
	a.renamed = ""
	if local.Instance != svc.InstanceName {
		a.renamed = local.Instance
	}
	return nil
}

// CommissionableInstanceName returns the instance name the commissionable
// service is published with, which differs from the one the device gave
// after a conflict, and false when it is not published.
func (a *MDNSAdvertiser) CommissionableInstanceName() (string, bool) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.current == nil {
		return "", false
	}
	return a.current.Instance, true
}

// HandleConflict handles a published service which the responder withdrew
// because another node holds one of its names (RFC 6762, 9). The
// commissionable service is published again with a new instance name, and
// an operational service is reported, and published again when the device
// next advertises its operational services. A conflict of a service this
// advertiser did not publish is ignored.
func (a *MDNSAdvertiser) HandleConflict(err *mdns.ConflictError) {
	if err == nil || err.Service == nil {
		return
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()

	name := err.Service.FullName()
	if a.current != nil && strings.EqualFold(a.current.FullName(), name) {
		a.current = nil
		if !err.IsInstanceConflict() {
			log.Errorf("device: the commissionable service is withdrawn: %v", err)
			return
		}
		local := *err.Service
		local.Instance = NewInstanceName()
		log.Warnf("device: commissionable instance name %s is used by another node, renamed to %s", err.Service.Instance, local.Instance)
		if regErr := a.registerCommissionableLocked(&local); regErr != nil {
			log.Errorf("device: publish the commissionable service again: %v", regErr)
			return
		}
		a.current = &local
		a.renamed = local.Instance
		return
	}
	for key, published := range a.operational {
		if strings.EqualFold(published.FullName(), name) {
			delete(a.operational, key)
			log.Errorf("device: the operational service is withdrawn, as another node uses its name: %v", err)
			return
		}
	}
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

// AdvertiseOperational implements Advertiser. It returns when the services
// are published, after the responder probes their names. A service whose
// name another node holds is not published, and its error wraps an
// *mdns.ConflictError.
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
		// An operational instance is named by its fabric and node ID, so
		// it is not renamed on a conflict.
		if err := a.register(local); err != nil {
			errs = append(errs, fmt.Errorf("device: advertise %s: %w", name, err))
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
