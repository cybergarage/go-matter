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

package crypto

import (
	"errors"
	"fmt"
)

// ErrInvalid is returned when an invalid operation is performed.
var ErrInvalid = errors.New("invalid")

func newErrInvalid(msg string) error {
	return fmt.Errorf("%w: %s", ErrInvalid, msg)
}

func newErrInvalidLen(name string, expected, got int) error {
	return fmt.Errorf("%w length for %s: expected %d, got %d", ErrInvalid, name, expected, got)
}
