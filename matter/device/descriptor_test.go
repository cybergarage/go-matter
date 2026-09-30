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
	"slices"
	"testing"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

func readUintList(t *testing.T, sess session.SecureSession, endpoint im.EndpointID, cluster im.ClusterID, attr im.AttributeID) []uint64 {
	t.Helper()
	var ids []uint64
	status, err := im.ReadListAttribute(sess, endpoint, cluster, attr, func(_ tlv.Decoder, item tlv.Element) error {
		v, _ := item.Unsigned()
		ids = append(ids, v)
		return nil
	})
	if err != nil || status != nil {
		t.Fatalf("read 0x%04X/0x%04X: (%+v, %v)", cluster, attr, status, err)
	}
	return ids
}

func TestDescriptorOfRootEndpoint(t *testing.T) {
	_, sess := startCommissioning(t)

	var deviceTypes []uint64
	status, err := im.ReadListAttribute(sess, 0, DescriptorClusterID, deviceTypeListAttributeID, func(dec tlv.Decoder, item tlv.Element) error {
		for dec.Next() {
			elem := dec.Element()
			if elem.Type().IsEndOfContainer() {
				break
			}
			if ct, ok := elem.Tag().(tlv.ContextTag); ok && ct.ContextNumber() == 0 {
				v, _ := elem.Unsigned()
				deviceTypes = append(deviceTypes, v)
			}
		}
		return dec.Error()
	})
	if err != nil || status != nil {
		t.Fatalf("read DeviceTypeList: (%+v, %v)", status, err)
	}
	if !slices.Equal(deviceTypes, []uint64{uint64(RootNodeDeviceType.ID)}) {
		t.Fatalf("DeviceTypeList = %v, want the Root Node", deviceTypes)
	}
	want := []uint64{
		uint64(DescriptorClusterID),
		uint64(BasicInformationClusterID),
		uint64(GeneralCommissioningClusterID),
		uint64(AdministratorCommissioningClusterID),
		uint64(OperationalCredentialsClusterID),
	}
	if got := readUintList(t, sess, 0, DescriptorClusterID, serverListAttributeID); !slices.Equal(got, want) {
		t.Fatalf("ServerList = %v, want %v", got, want)
	}
	if got := readUintList(t, sess, 0, DescriptorClusterID, partsListAttributeID); len(got) != 0 {
		t.Fatalf("PartsList = %v, want none", got)
	}
	if got := readUintList(t, sess, 0, GeneralCommissioningClusterID, im.GeneratedCommandListAttributeID); !slices.Equal(got, []uint64{0x01, 0x03, 0x05}) {
		t.Fatalf("General Commissioning GeneratedCommandList = %v", got)
	}
}

func TestBasicInformationNodeLabel(t *testing.T) {
	_, sess := startCommissioning(t)
	resp, err := im.WriteAttribute(sess, 0, BasicInformationClusterID, nodeLabelAttributeID, func(enc tlv.Encoder) error {
		return enc.PutUTF8(tlv.NewContextTag(2), "kitchen light")
	})
	if err != nil || !resp.IsSuccess() {
		t.Fatalf("write NodeLabel: (%+v, %v)", resp, err)
	}
	read, err := im.ReadAttribute(sess, 0, BasicInformationClusterID, nodeLabelAttributeID)
	if err != nil || read.Status != nil {
		t.Fatalf("read NodeLabel: (%+v, %v)", read, err)
	}
	if v, _ := read.Value.UTF8(); v != "kitchen light" {
		t.Fatalf("NodeLabel = %q, want the label written", v)
	}
	resp, err = im.WriteAttribute(sess, 0, BasicInformationClusterID, vendorIDAttributeID, func(enc tlv.Encoder) error {
		enc.PutUnsigned2(tlv.NewContextTag(2), 1)
		return nil
	})
	if err != nil || resp.Status.IMStatus != uint8(im.StatusUnsupportedWrite) {
		t.Fatalf("write VendorID: (%+v, %v), want UnsupportedWrite", resp, err)
	}
}
