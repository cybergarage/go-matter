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

package matter

// Commissioner represents a commissioner.
type Commissioner struct {
	*Discoverer
}

// NewCommissioner returns a new commissioner.
func NewCommissioner() *Commissioner {
	com := &Commissioner{
		Discoverer: NewDiscoverer(),
	}
	return com
}

// Start starts the commissioner.
func (com *Commissioner) Start() error {
	err := com.Discoverer.Start()
	if err != nil {
		return err
	}

	return nil
}

// Stop stops the commissioner.
func (com *Commissioner) Stop() error {
	err := com.Discoverer.Stop()
	if err != nil {
		return err
	}

	return nil
}
