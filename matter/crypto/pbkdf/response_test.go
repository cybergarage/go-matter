// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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

package pbkdf

import (
	"reflect"
	"testing"
)

func TestResponseDefault(t *testing.T) {
	req := NewParamRequest()
	resp, err := NewParamResponse(WithParamResponseParamRequest(req))
	if err != nil {
		t.Fatal(err)
	}
	respBytes, err := resp.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	respParsed, err := NewParamResponseFromBytes(respBytes)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(resp.Map(), respParsed.Map()) {
		t.Errorf("%v != %v", resp.Map(), respParsed.Map())
	}
}
