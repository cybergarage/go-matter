// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package pbkdf

import (
	"errors"
	"fmt"

	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

var ErrMissingRequiredField = errors.New("missing required field")

func newErrMissingRequiredField(fieldName string) error {
	return fmt.Errorf("%w: %s", ErrMissingRequiredField, fieldName)
}

func expectedTypeError(expected tlv.ElementType, actual tlv.Element) error {
	return fmt.Errorf("expected %s, got %s", expected, actual.Type())
}

func expectedTagError(expected tlv.TagControl, actual tlv.Tag) error {
	return fmt.Errorf("expected tag type %s, got %s", expected, actual.Control())
}

func checkInitiatorRandomLength(name string, b []byte, expectedLength int) error {
	if b == nil {
		return newErrMissingRequiredField(name)
	}
	if len(b) != expectedLength {
		return fmt.Errorf("invalid %s length: expected %d, got %d", name, expectedLength, len(b))
	}
	return nil
}
