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
	"sync"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/store"
)

// CommissioningError is the CommissioningErrorEnum the General
// Commissioning commands answer with (Matter Core 11.10.4.1).
type CommissioningError uint8

const (
	CommissioningOK                    CommissioningError = 0
	CommissioningValueOutsideRange     CommissioningError = 1
	CommissioningInvalidAuthentication CommissioningError = 2
	CommissioningNoFailSafe            CommissioningError = 3
	CommissioningBusyWithOtherAdmin    CommissioningError = 4
)

// Fail-safe limits (Matter Core 11.10.5.2): how long one ArmFailSafe arms
// the fail-safe by default, and how long it can stay armed in all.
const (
	DefaultFailSafeExpiryLength       = 60 * time.Second
	DefaultMaxCumulativeFailSafeLimit = 900 * time.Second
)

// timerFunc starts f after d, returning a function which stops it, as
// time.AfterFunc does; tests replace it.
type timerFunc func(d time.Duration, f func()) (stop func() bool)

func realTimer(d time.Duration, f func()) func() bool {
	return time.AfterFunc(d, f).Stop
}

// failSafe is the commissioning fail-safe (Matter Core 11.10.6.2): while it
// is armed, the changes commissioning makes are written through a
// DeviceStore transaction, committed by CommissioningComplete and rolled
// back when the fail-safe expires or is disarmed.
type failSafe struct {
	mutex         sync.Mutex
	store         store.DeviceStore
	now           func() time.Time
	timer         timerFunc
	maxCumulative time.Duration
	onExpire      func()
	// onRollback is called, with the fail-safe's lock held, on every
	// rollback, with the fabric AddNOC added under it, or 0 when there is
	// none, as when the rollback undoes an UpdateNOC; it must not call
	// back into the fail-safe.
	onRollback func(addedFabric uint8)

	armed      bool
	fabric     uint8
	added      uint8
	tx         store.DeviceStoreTx
	firstArmed time.Time
	stop       func() bool
	generation int
	// epoch counts the times the fail-safe has been armed from disarmed,
	// so state staged while it was armed can tell whether it still is.
	epoch uint64
}

func newFailSafe(s store.DeviceStore) *failSafe {
	return &failSafe{
		mutex:         sync.Mutex{},
		store:         s,
		now:           time.Now,
		timer:         realTimer,
		maxCumulative: DefaultMaxCumulativeFailSafeLimit,
		onExpire:      nil,
		onRollback:    nil,
		armed:         false,
		fabric:        0,
		added:         0,
		tx:            nil,
		firstArmed:    time.Time{},
		stop:          nil,
		generation:    0,
		epoch:         0,
	}
}

// arm arms the fail-safe for expiry on behalf of fabric (0 for a PASE
// session, which has none), or extends it when that fabric armed it. A zero
// expiry disarms it, rolling back what it guarded (11.10.7.2).
func (fs *failSafe) arm(fabric uint8, expiry time.Duration) CommissioningError {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	if fs.armed && fs.fabric != fabric {
		return CommissioningBusyWithOtherAdmin
	}
	if expiry <= 0 {
		if fs.armed {
			fs.rollbackLocked()
		}
		return CommissioningOK
	}
	now := fs.now()
	if !fs.armed {
		tx, err := fs.store.Begin()
		if err != nil {
			log.Errorf("device: fail-safe: begin a transaction: %v", err)
			return CommissioningBusyWithOtherAdmin
		}
		fs.armed = true
		fs.fabric = fabric
		fs.tx = tx
		fs.firstArmed = now
		fs.epoch++
	}
	// The fail-safe never stays armed past the cumulative limit counted
	// from when it was first armed (11.10.5.2).
	deadline := now.Add(expiry)
	if limit := fs.firstArmed.Add(fs.maxCumulative); limit.Before(deadline) {
		deadline = limit
	}
	if fs.stop != nil {
		fs.stop()
	}
	fs.generation++
	gen := fs.generation
	fs.stop = fs.timer(deadline.Sub(now), func() { fs.expire(gen) })
	return CommissioningOK
}

// expire rolls back when the timer of arming gen fires, unless the
// fail-safe was re-armed, disarmed or committed since.
func (fs *failSafe) expire(gen int) {
	fs.mutex.Lock()
	if !fs.armed || gen != fs.generation {
		fs.mutex.Unlock()
		return
	}
	log.Infof("device: the fail-safe expired; rolling back the commissioning changes")
	fs.rollbackLocked()
	onExpire := fs.onExpire
	fs.mutex.Unlock()
	if onExpire != nil {
		onExpire()
	}
}

func (fs *failSafe) rollbackLocked() {
	if err := fs.tx.Rollback(); err != nil {
		log.Errorf("device: fail-safe: roll back: %v", err)
	}
	if fs.onRollback != nil {
		fs.onRollback(fs.added)
	}
	fs.disarmLocked()
}

func (fs *failSafe) disarmLocked() {
	if fs.stop != nil {
		fs.stop()
	}
	fs.generation++
	fs.armed = false
	fs.fabric = 0
	fs.added = 0
	fs.tx = nil
	fs.stop = nil
}

// commit commits what the fail-safe guarded and disarms it, when fabric
// is the fabric associated with it (CommissioningComplete, 11.10.7.6).
func (fs *failSafe) commit(fabric uint8) (CommissioningError, error) {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	if !fs.armed {
		return CommissioningNoFailSafe, nil
	}
	if fabric != fs.fabric {
		return CommissioningInvalidAuthentication, nil
	}
	err := fs.tx.Commit()
	fs.disarmLocked()
	return CommissioningOK, err
}

// transaction returns the transaction commissioning writes through, or nil
// when the fail-safe is not armed.
func (fs *failSafe) transaction() store.DeviceStoreTx {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.tx
}

// addFabric associates the fail-safe with the fabric AddNOC added under
// it: from then on it is that fabric's to extend and complete, and a
// rollback removes it (11.18.6.8).
func (fs *failSafe) addFabric(fabric uint8) {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	if fs.armed {
		fs.fabric = fabric
		fs.added = fabric
	}
}

// armedTransaction returns the transaction and the epoch of the arming in
// progress, or a nil transaction when the fail-safe is not armed.
func (fs *failSafe) armedTransaction() (store.DeviceStoreTx, uint64) {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.tx, fs.epoch
}

// armedFabric returns the fabric the armed fail-safe is associated with,
// 0 when it is not armed or was armed over PASE.
func (fs *failSafe) armedFabric() uint8 {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	if !fs.armed {
		return 0
	}
	return fs.fabric
}

func (fs *failSafe) isArmed() bool {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	return fs.armed
}

// close rolls back an armed fail-safe, as a device stopping does.
func (fs *failSafe) close() {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	if fs.armed {
		fs.rollbackLocked()
	}
}
