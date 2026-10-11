// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package im

import "github.com/cybergarage/go-matter/matter/encoding/tlv"

// AttributeValue retains an exact TLV type and tag, scalar data, and ordered
// children. Empty containers have zero children; Null remains a scalar element.
// EndOfContainer markers are consumed, not represented as children.
type AttributeValue struct {
	Element  tlv.Element
	Children []*AttributeValue
}

// ValueReadResponse contains either a complete observed value or a device status,
// never both. A successful status without Data is not an observed value.
type ValueReadResponse struct {
	Status *InvokeStatus
	Value  *AttributeValue
}

// Read limits apply to the entire decrypted response, including unknown fields.
// They bound allocation and recursion before any value can be returned.
const (
	MaxValueReadBytes    = 1 << 20
	MaxValueReadDepth    = 32
	MaxValueReadElements = 4096
)
