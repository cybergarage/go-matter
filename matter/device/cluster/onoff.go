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

package cluster

import (
	"sync"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// On/Off cluster (Matter Application Cluster 1.5).
const (
	OnOffClusterID im.ClusterID = 0x0006

	OnOffAttributeID              im.AttributeID = 0x0000
	GlobalSceneControlAttributeID im.AttributeID = 0x4000
	OnTimeAttributeID             im.AttributeID = 0x4001
	OffWaitTimeAttributeID        im.AttributeID = 0x4002
	StartUpOnOffAttributeID       im.AttributeID = 0x4003

	OffCommandID                     im.CommandID = 0x00
	OnCommandID                      im.CommandID = 0x01
	ToggleCommandID                  im.CommandID = 0x02
	OffWithEffectCommandID           im.CommandID = 0x40
	OnWithRecallGlobalSceneCommandID im.CommandID = 0x41
	OnWithTimedOffCommandID          im.CommandID = 0x42

	// OnOffFeatureLighting is the Lighting feature (LT) an On/Off Light
	// requires (1.5.4).
	OnOffFeatureLighting uint32 = 0x01

	onOffClusterRevision = 6

	featureMapAttributeID      im.AttributeID = 0xFFFC
	clusterRevisionAttributeID im.AttributeID = 0xFFFD
	onWithTimedOffAcceptOnlyOn                = 0x01
	startUpOnOffToggle                        = 0x02
	startUpOnOffMax                           = startUpOnOffToggle
)

// OnOff is the server of the On/Off cluster with the Lighting feature: it
// keeps the OnOff attribute, which the On, Off and Toggle commands and
// their Lighting variants change, and calls the application's handler on
// every change so it can drive the hardware.
type OnOff struct {
	mutex              sync.Mutex
	endpoint           Endpoint
	on                 bool
	globalSceneControl bool
	onTime             uint16
	offWaitTime        uint16
	startUpOnOff       *uint8
	delayedOff         *time.Timer
	offGeneration      uint64
	invalidateScene    func()
	onChange           func(on bool)
}

// OnOffOption configures an OnOff.
type OnOffOption func(*OnOff)

// WithOnOffHandler sets the function called whenever OnOff changes, with
// its new value.
func WithOnOffHandler(h func(on bool)) OnOffOption {
	return func(c *OnOff) {
		c.onChange = h
	}
}

// WithInitialOnOff sets the value OnOff starts with.
func WithInitialOnOff(on bool) OnOffOption {
	return func(c *OnOff) {
		c.on = on
	}
}

// NewOnOff returns an On/Off cluster server, off unless an option says
// otherwise.
func NewOnOff(opts ...OnOffOption) *OnOff {
	c := &OnOff{
		mutex:              sync.Mutex{},
		endpoint:           nil,
		on:                 false,
		globalSceneControl: true,
		onTime:             0,
		offWaitTime:        0,
		startUpOnOff:       nil,
		delayedOff:         nil,
		offGeneration:      0,
		invalidateScene:    nil,
		onChange:           nil,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Register serves the cluster on ep.
func (c *OnOff) Register(ep Endpoint) {
	c.mutex.Lock()
	c.endpoint = ep
	c.mutex.Unlock()

	ep.HandleAttribute(OnOffClusterID, OnOffAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutBool(tag, c.On())
		return im.StatusSuccess
	})
	ep.HandleAttribute(OnOffClusterID, GlobalSceneControlAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		enc.PutBool(tag, c.globalSceneControl)
		return im.StatusSuccess
	})
	c.handleUint16(ep, OnTimeAttributeID, &c.onTime)
	c.handleUint16(ep, OffWaitTimeAttributeID, &c.offWaitTime)
	ep.HandleAttribute(OnOffClusterID, StartUpOnOffAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		if c.startUpOnOff == nil {
			enc.PutNull(tag)
		} else {
			enc.PutUnsigned1(tag, *c.startUpOnOff)
		}
		return im.StatusSuccess
	})
	ep.HandleAttributeWrite(OnOffClusterID, StartUpOnOffAttributeID, func(req *im.AttributeWriteRequest) im.Status {
		_, elem, err := req.Decoder()
		if err != nil {
			return im.StatusInvalidDataType
		}
		c.mutex.Lock()
		defer c.mutex.Unlock()
		if elem.Type().IsNull() {
			c.startUpOnOff = nil
			return im.StatusSuccess
		}
		v, ok := elem.Unsigned()
		if !ok {
			return im.StatusInvalidDataType
		}
		if startUpOnOffMax < v {
			return im.StatusConstraintError
		}
		b := uint8(v)
		c.startUpOnOff = &b
		return im.StatusSuccess
	}, im.WithPrivilege(im.PrivilegeManage))
	ep.HandleAttribute(OnOffClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, OnOffFeatureLighting)
		return im.StatusSuccess
	})
	ep.HandleAttribute(OnOffClusterID, clusterRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, onOffClusterRevision)
		return im.StatusSuccess
	})

	ep.HandleCommand(OnOffClusterID, OffCommandID, func(*im.CommandRequest) im.CommandResult {
		c.Set(false)
		return im.CommandStatus(im.StatusSuccess)
	})
	ep.HandleCommand(OnOffClusterID, OnCommandID, func(*im.CommandRequest) im.CommandResult {
		c.Set(true)
		return im.CommandStatus(im.StatusSuccess)
	})
	ep.HandleCommand(OnOffClusterID, ToggleCommandID, func(*im.CommandRequest) im.CommandResult {
		c.Toggle()
		return im.CommandStatus(im.StatusSuccess)
	})
	ep.HandleCommand(OnOffClusterID, OffWithEffectCommandID, func(*im.CommandRequest) im.CommandResult {
		// The effect itself is the hardware's; the cluster turns off and
		// keeps the global scene control (1.5.7.4).
		c.mutex.Lock()
		c.globalSceneControl = false
		c.mutex.Unlock()
		c.endpoint.NotifyAttributeChanged(OnOffClusterID, GlobalSceneControlAttributeID)
		c.Set(false)
		return im.CommandStatus(im.StatusSuccess)
	})
	ep.HandleCommand(OnOffClusterID, OnWithRecallGlobalSceneCommandID, func(*im.CommandRequest) im.CommandResult {
		c.mutex.Lock()
		changed := !c.globalSceneControl
		c.globalSceneControl = true
		c.mutex.Unlock()
		if changed {
			c.endpoint.NotifyAttributeChanged(OnOffClusterID, GlobalSceneControlAttributeID)
		}
		c.Set(true)
		return im.CommandStatus(im.StatusSuccess)
	})
	ep.HandleCommand(OnOffClusterID, OnWithTimedOffCommandID, c.onWithTimedOff)
}

func (c *OnOff) handleUint16(ep Endpoint, attribute im.AttributeID, v *uint16) {
	ep.HandleAttribute(OnOffClusterID, attribute, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		enc.PutUnsigned2(tag, *v)
		return im.StatusSuccess
	})
	ep.HandleAttributeWrite(OnOffClusterID, attribute, func(req *im.AttributeWriteRequest) im.Status {
		_, elem, err := req.Decoder()
		if err != nil {
			return im.StatusInvalidDataType
		}
		n, ok := elem.Unsigned()
		if !ok {
			return im.StatusInvalidDataType
		}
		if 0xFFFF < n {
			return im.StatusConstraintError
		}
		c.mutex.Lock()
		defer c.mutex.Unlock()
		*v = uint16(n)
		return im.StatusSuccess
	})
}

// onWithTimedOff turns on for OnTime tenths of a second (1.5.7.6). The
// countdown is not reflected in the OnTime attribute; the light turns off
// when it ends.
func (c *OnOff) onWithTimedOff(req *im.CommandRequest) im.CommandResult {
	control, _ := unsignedField(req, 0)
	onTime, ok1 := unsignedField(req, 1)
	offWaitTime, ok2 := unsignedField(req, 2)
	if !ok1 || !ok2 || 0xFFFE < onTime || 0xFFFE < offWaitTime {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	if control&onWithTimedOffAcceptOnlyOn != 0 && !c.On() {
		return im.CommandStatus(im.StatusSuccess)
	}
	c.mutex.Lock()
	c.onTime = max(c.onTime, uint16(onTime))
	c.offWaitTime = uint16(offWaitTime)
	d := time.Duration(c.onTime) * 100 * time.Millisecond
	if c.delayedOff != nil {
		c.delayedOff.Stop()
	}
	c.offGeneration++
	generation := c.offGeneration
	c.delayedOff = time.AfterFunc(d, func() {
		c.update(func(on bool) bool { return on && generation != c.offGeneration })
	})
	c.mutex.Unlock()
	c.endpoint.NotifyAttributeChanged(OnOffClusterID, OnTimeAttributeID)
	c.endpoint.NotifyAttributeChanged(OnOffClusterID, OffWaitTimeAttributeID)
	c.Set(true)
	return im.CommandStatus(im.StatusSuccess)
}

// On returns the OnOff attribute.
func (c *OnOff) On() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.on
}

// Set changes the OnOff attribute, as the commands do; an application
// calls it when the hardware changes by itself, such as by a wall switch.
func (c *OnOff) Set(on bool) {
	c.update(func(bool) bool { return on })
}

// Toggle inverts the OnOff attribute.
func (c *OnOff) Toggle() {
	c.update(func(on bool) bool { return !on })
}

// update sets OnOff to next of its value, then tells the application and
// the subscriptions if it changed.
func (c *OnOff) update(next func(on bool) bool) {
	c.mutex.Lock()
	on := next(c.on)
	changed := c.on != on
	c.on = on
	if !on && c.delayedOff != nil {
		c.delayedOff.Stop()
		c.delayedOff = nil
		c.offGeneration++
	}
	ep := c.endpoint
	handler := c.onChange
	invalidateScene := c.invalidateScene
	c.mutex.Unlock()
	if !changed {
		return
	}
	if handler != nil {
		handler(on)
	}
	if invalidateScene != nil {
		invalidateScene()
	}
	if ep != nil {
		ep.NotifyAttributeChanged(OnOffClusterID, OnOffAttributeID)
	}
}

func unsignedField(req *im.CommandRequest, tag uint8) (uint64, bool) {
	elem, ok := req.Field(tag)
	if !ok {
		return 0, false
	}
	return elem.Unsigned()
}

// SceneValues returns the OnOff attribute, which a scene stores.
func (c *OnOff) SceneValues() []SceneAttributeValue {
	v := uint64(0)
	if c.On() {
		v = 1
	}
	return []SceneAttributeValue{{Attribute: OnOffAttributeID, Value: v, Signed: false, Bits: 8}}
}

// RecallScene sets the OnOff attribute a scene stores; the transition
// does not apply to switching on or off.
func (c *OnOff) RecallScene(values []SceneAttributeValue, _ time.Duration) {
	for _, v := range values {
		if v.Attribute == OnOffAttributeID {
			c.Set(v.Value != 0)
		}
	}
}

func (c *OnOff) setSceneInvalidator(invalidate func()) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.invalidateScene = invalidate
}
