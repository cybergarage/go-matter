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

// ParamRequest represents a PASE parameter request.
type ParamRequest interface {
	Bytes() []byte
}

type paramRequest struct {
	bytes []byte
}

func NewParamRequest() ParamRequest {
	// 4.14.1. Passcode-Authenticated Session Establishment (PASE) - PBKDFParamRequest
	return &paramRequest{
		bytes: []byte{opPBKDFParamRequest},
	}
}

// Bytes returns the byte representation of the parameter request.
func (req *paramRequest) Bytes() []byte {
	return req.bytes
}

// ParamResponse represents a PASE parameter response.
type ParamResponse interface {
	Bytes() []byte
}

type paramResoponse struct {
	bytes []byte
}

// Bytes returns the byte representation of the parameter response.
func (res *paramResoponse) Bytes() []byte {
	return res.bytes
}
