// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package errors

import (
	"errors"
)

var (
	// ErrInvalid indicates an invalid error.
	ErrInvalid = errors.New("invalid")
	// ErrNotFound indicates that a requested resource was not found.
	ErrNotFound = errors.New("not found")
)

// Is reports whether any error in err's chain matches target.
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in err's chain that matches target, and if so, sets target to that error value and returns true.
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}
