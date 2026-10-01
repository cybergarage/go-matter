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

// Package groupkeymanagement provides a client for the Matter Group Key
// Management cluster (0x003F), which a commissioner configures a node's
// group keys with before it sends to groups.
// Reference: Matter Core Spec 1.5, Section 11.2.
package groupkeymanagement

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

// ClusterID is the Group Key Management cluster identifier.
const ClusterID im.ClusterID = 0x003F

// Attribute and command IDs of the Group Key Management cluster.
const (
	GroupKeyMapAttributeID im.AttributeID = 0x0000

	KeySetWriteCommandID  im.CommandID = 0x00
	KeySetRemoveCommandID im.CommandID = 0x03
)

// EpochKey is an epoch key of a group key set and the time, in
// microseconds since the Matter epoch, it starts being used.
type EpochKey struct {
	Key       []byte
	StartTime uint64
}

// GroupKeyMapEntry maps a group to the key set its messages use.
type GroupKeyMapEntry struct {
	GroupID       uint16
	GroupKeySetID uint16
}

// KeySetWrite writes a group key set, other than the IPK (key set 0), of
// one to three epoch keys in order of their start times, with the
// TrustFirst security policy, on the accessing fabric.
func KeySetWrite(sess session.SecureSession, keySetID uint16, keys []EpochKey) error {
	if len(keys) == 0 || 3 < len(keys) {
		return fmt.Errorf("groupkeymanagement: a key set has 1 to 3 epoch keys, not %d", len(keys))
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.BeginStructure(tlv.NewContextTag(0)) // GroupKeySetStruct
	enc.PutUnsigned2(tlv.NewContextTag(0), keySetID)
	enc.PutUnsigned1(tlv.NewContextTag(1), 0) // TrustFirst
	for i := range 3 {
		keyTag, startTag := tlv.NewContextTag(uint8(2+2*i)), tlv.NewContextTag(uint8(3+2*i)) // nolint: gosec // 2 to 7
		if i < len(keys) {
			if err := enc.PutOctet(keyTag, keys[i].Key); err != nil {
				return err
			}
			enc.PutUnsigned8(startTag, keys[i].StartTime)
		} else {
			enc.PutNull(keyTag)
			enc.PutNull(startTag)
		}
	}
	if err := enc.EndContainer(); err != nil {
		return err
	}
	if err := enc.EndContainer(); err != nil {
		return err
	}
	resp, err := im.Invoke(sess, 0, ClusterID, KeySetWriteCommandID, enc.Bytes())
	if err != nil {
		return fmt.Errorf("groupkeymanagement: KeySetWrite: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("groupkeymanagement: KeySetWrite failed: IM status 0x%02X", resp.Status.IMStatus)
	}
	return nil
}

// KeySetRemove removes a group key set, and the groups mapped to it.
func KeySetRemove(sess session.SecureSession, keySetID uint16) error {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned2(tlv.NewContextTag(0), keySetID)
	if err := enc.EndContainer(); err != nil {
		return err
	}
	resp, err := im.Invoke(sess, 0, ClusterID, KeySetRemoveCommandID, enc.Bytes())
	if err != nil {
		return fmt.Errorf("groupkeymanagement: KeySetRemove: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("groupkeymanagement: KeySetRemove failed: IM status 0x%02X", resp.Status.IMStatus)
	}
	return nil
}

// WriteGroupKeyMap replaces the accessing fabric's GroupKeyMap: which key
// set each group's messages use.
func WriteGroupKeyMap(sess session.SecureSession, entries []GroupKeyMapEntry) error {
	resp, err := im.WriteAttribute(sess, 0, ClusterID, GroupKeyMapAttributeID, func(enc tlv.Encoder) error {
		enc.BeginArray(tlv.NewContextTag(2))
		for _, e := range entries {
			enc.BeginStructure(tlv.NewAnonymousTag())
			enc.PutUnsigned2(tlv.NewContextTag(1), e.GroupID)
			enc.PutUnsigned2(tlv.NewContextTag(2), e.GroupKeySetID)
			if err := enc.EndContainer(); err != nil {
				return err
			}
		}
		return enc.EndContainer()
	})
	if err != nil {
		return fmt.Errorf("groupkeymanagement: write GroupKeyMap: %w", err)
	}
	if !resp.IsSuccess() {
		return fmt.Errorf("groupkeymanagement: write GroupKeyMap failed: IM status 0x%02X", resp.Status.IMStatus)
	}
	return nil
}
