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

package message

import (
	"errors"
)

var (
	// ErrInvalidFrameLength indicates the raw buffer is too short or inconsistent.
	ErrInvalidFrameLength = errors.New("invalid frame length")
	// ErrUnknownVersion indicates the frame version is not supported by the codec.
	ErrUnknownVersion = errors.New("unknown frame version")
	// ErrBufferTooSmall indicates the destination buffer passed to EncodeInto is insufficient.
	ErrBufferTooSmall = errors.New("buffer too small for frame")
	// ErrMICLengthMismatch indicates a MIC length outside accepted bounds.
	ErrMICLengthMismatch = errors.New("mic length mismatch")
	// ErrPayloadMissing indicates a required payload is absent (nil).
	ErrPayloadMissing = errors.New("payload missing")
)
