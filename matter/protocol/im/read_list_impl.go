// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

package im

import (
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

// ReadListAttribute reads a single List- or Array-typed attribute and
// streams its items to itemFn as each is decoded off the same tlv.Decoder,
// instead of buffering the whole list — a tlv.Element cannot hold a
// container's contents, only ReadAttribute's scalar case. itemFn is called
// once per item, in order; when an item is itself a container (e.g.
// Descriptor's DeviceTypeStruct), itemFn must fully consume it, including
// its own EndOfContainer marker, via dec.Next() before returning — the same
// convention this package's other nested-IB parsers already follow (see
// skipContainer / parseFlatFields in invoke_impl.go).
//
// Returns the AttributeStatusIB/StatusResponseMessage status, if any (nil on
// success); itemFn is not called at all when the device reported a status
// instead of attribute data. This is still a single concrete attribute path
// — no wildcard reads.
func ReadListAttribute(sess SecureSession, endpointID EndpointID, clusterID ClusterID, attributeID AttributeID, itemFn func(dec tlv.Decoder, item tlv.Element) error) (*InvokeStatus, error) {
	responseRaw, err := doReadRequest(sess, endpointID, clusterID, attributeID)
	if err != nil {
		return nil, err
	}

	var haveContainer bool
	return parseReadResponseCore(responseRaw, func(dec tlv.Decoder, elem tlv.Element) error {
		return decodeListAttributeData(dec, elem, &haveContainer, itemFn)
	})
}

// decodeListAttributeData handles one AttributeReportIB's Data element
// (10.6.3, tag 2) toward reassembling a List/Array-typed attribute's value,
// which a server may split across multiple reports (10.5.4.3, "List
// Chunking"): an initiating report whose Data is the (possibly empty) whole
// array, followed by zero or more single-item "append" reports — each with
// Data holding just that one item directly, not wrapped in another array —
// that parseAttributeReportIBsCore now feeds this function one at a time,
// in order, instead of stopping after the first. *haveContainer tracks
// whether the initiating report has been seen yet, shared across every
// call for one ReadListAttribute invocation via the closure in
// ReadListAttribute above. Split out from ReadListAttribute so it can also
// be driven directly against a hand-built ReadResponse payload in tests,
// without needing a matching Interaction Model exchange over a session.
func decodeListAttributeData(dec tlv.Decoder, elem tlv.Element, haveContainer *bool, itemFn func(dec tlv.Decoder, item tlv.Element) error) error {
	if !*haveContainer {
		if !elem.Type().IsList() && !elem.Type().IsArray() {
			return fmt.Errorf("im: ReadListAttribute: attribute value is not a List/Array (%v)", elem.Type())
		}
		*haveContainer = true
		for dec.Next() {
			item := dec.Element()
			if item.Type().IsEndOfContainer() {
				return dec.Error()
			}
			if err := itemFn(dec, item); err != nil {
				return err
			}
		}
		return dec.Error()
	}
	// A later chunk-append report: elem is the single appended item
	// itself, not a container of items — hand it to itemFn directly, the
	// same as any other item it would otherwise stream off the initiating
	// report's own container.
	return itemFn(dec, elem)
}
