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

package pase

import (
	"github.com/cybergarage/go-matter/matter/encoding"
)

// Session represents a PASE session.
type Session interface {
}

// SessionOption represents a session option.
type SessionOption func(*session)

// Passcode represents a passcode.
type Passcode = encoding.Passcode

// WithPasscode returns a session option that sets the passcode.
func WithPasscode(passcode Passcode) SessionOption {
	return func(sess *session) {
		sess.passcode = passcode
	}
}

type session struct {
	passcode Passcode
}

// NewSessionWith returns a new PASE session with the given options.
func NewSessionWith(options ...SessionOption) Session {
	sess := &session{
		passcode: 0,
	}
	for _, opt := range options {
		opt(sess)
	}
	return sess
}
