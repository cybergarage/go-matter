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

// Identify cluster (Matter Application Cluster 1.2).
const (
	IdentifyClusterID im.ClusterID = 0x0003

	IdentifyTimeAttributeID im.AttributeID = 0x0000
	IdentifyTypeAttributeID im.AttributeID = 0x0001

	IdentifyCommandID      im.CommandID = 0x00
	TriggerEffectCommandID im.CommandID = 0x40

	identifyClusterRevision = 5
)

// IdentifyType is how an endpoint identifies itself (1.2.5.1).
type IdentifyType uint8

// Identify types.
const (
	IdentifyTypeNone             IdentifyType = 0x00
	IdentifyTypeLightOutput      IdentifyType = 0x01
	IdentifyTypeVisibleIndicator IdentifyType = 0x02
	IdentifyTypeAudibleBeep      IdentifyType = 0x03
	IdentifyTypeDisplay          IdentifyType = 0x04
	IdentifyTypeActuator         IdentifyType = 0x05
)

// Identify is the server of the Identify cluster: it counts IdentifyTime
// down to zero, and tells the application when identification starts
// and stops, and which effect TriggerEffect asks for.
type Identify struct {
	mutex        sync.Mutex
	endpoint     Endpoint
	identifyType IdentifyType
	until        time.Time
	identifying  bool
	generation   uint64
	timer        *time.Timer
	onIdentify   func(identifying bool)
	onEffect     func(effect, variant uint8)
}

// IdentifyOption configures an Identify.
type IdentifyOption func(*Identify)

// WithIdentifyHandler sets the function called when identification starts
// and stops.
func WithIdentifyHandler(h func(identifying bool)) IdentifyOption {
	return func(c *Identify) {
		c.onIdentify = h
	}
}

// WithEffectHandler sets the function called for TriggerEffect with its
// effect identifier and variant (1.2.6.2).
func WithEffectHandler(h func(effect, variant uint8)) IdentifyOption {
	return func(c *Identify) {
		c.onEffect = h
	}
}

// NewIdentify returns an Identify cluster server of identifyType.
func NewIdentify(identifyType IdentifyType, opts ...IdentifyOption) *Identify {
	c := &Identify{
		mutex:        sync.Mutex{},
		endpoint:     nil,
		identifyType: identifyType,
		until:        time.Time{},
		identifying:  false,
		generation:   0,
		timer:        nil,
		onIdentify:   nil,
		onEffect:     nil,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Register serves the cluster on ep.
func (c *Identify) Register(ep Endpoint) {
	c.mutex.Lock()
	c.endpoint = ep
	c.mutex.Unlock()

	ep.HandleAttribute(IdentifyClusterID, IdentifyTimeAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, c.IdentifyTime())
		return im.StatusSuccess
	})
	ep.HandleAttributeWrite(IdentifyClusterID, IdentifyTimeAttributeID, func(req *im.AttributeWriteRequest) im.Status {
		_, elem, err := req.Decoder()
		if err != nil {
			return im.StatusInvalidDataType
		}
		v, ok := elem.Unsigned()
		if !ok {
			return im.StatusInvalidDataType
		}
		if 0xFFFF < v {
			return im.StatusConstraintError
		}
		c.start(uint16(v))
		return im.StatusSuccess
	})
	ep.HandleAttribute(IdentifyClusterID, IdentifyTypeAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned1(tag, uint8(c.identifyType))
		return im.StatusSuccess
	})
	ep.HandleAttribute(IdentifyClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, 0)
		return im.StatusSuccess
	})
	ep.HandleAttribute(IdentifyClusterID, clusterRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, identifyClusterRevision)
		return im.StatusSuccess
	})
	ep.HandleCommand(IdentifyClusterID, IdentifyCommandID, func(req *im.CommandRequest) im.CommandResult {
		v, ok := unsignedField(req, 0)
		if !ok || 0xFFFF < v {
			return im.CommandStatus(im.StatusInvalidCommand)
		}
		c.start(uint16(v))
		return im.CommandStatus(im.StatusSuccess)
	})
	ep.HandleCommand(IdentifyClusterID, TriggerEffectCommandID, func(req *im.CommandRequest) im.CommandResult {
		effect, ok1 := unsignedField(req, 0)
		variant, ok2 := unsignedField(req, 1)
		if !ok1 || !ok2 || 0xFF < effect || 0xFF < variant {
			return im.CommandStatus(im.StatusInvalidCommand)
		}
		c.mutex.Lock()
		h := c.onEffect
		c.mutex.Unlock()
		if h != nil {
			h(uint8(effect), uint8(variant))
		}
		return im.CommandStatus(im.StatusSuccess)
	})
}

// IdentifyTime returns the seconds left of identification.
func (c *Identify) IdentifyTime() uint16 {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	left := time.Until(c.until)
	if left <= 0 {
		return 0
	}
	return uint16(min((left+time.Second-1)/time.Second, 0xFFFF)) // nolint: gosec // bounded above
}

// start identifies for seconds, or stops identifying for zero.
func (c *Identify) start(seconds uint16) {
	c.mutex.Lock()
	c.startLocked(seconds)
}

// expire stops the identification of generation, unless a later start
// replaced it.
func (c *Identify) expire(generation uint64) {
	c.mutex.Lock()
	if generation != c.generation {
		c.mutex.Unlock()
		return
	}
	c.startLocked(0)
}

// startLocked is start with the mutex held, which it releases.
func (c *Identify) startLocked(seconds uint16) {
	c.generation++
	generation := c.generation
	wasIdentifying := c.identifying
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	identifying := 0 < seconds
	if identifying {
		c.until = time.Now().Add(time.Duration(seconds) * time.Second)
		c.timer = time.AfterFunc(time.Duration(seconds)*time.Second, func() { c.expire(generation) })
	} else {
		c.until = time.Time{}
	}
	c.identifying = identifying
	ep := c.endpoint
	h := c.onIdentify
	c.mutex.Unlock()
	if ep != nil {
		ep.NotifyAttributeChanged(IdentifyClusterID, IdentifyTimeAttributeID)
	}
	if h != nil && identifying != wasIdentifying {
		h(identifying)
	}
}
