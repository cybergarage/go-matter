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

type query struct {
	payload OnboardingPayload
}

// QueryOption represents an option for creating a Query.
type QueryOption func(*query)

// WithQueryOnboardingPayload sets the onboarding payload for the query.
func WithQueryOnboardingPayload(payload OnboardingPayload) QueryOption {
	return func(q *query) {
		q.payload = payload
	}
}

// NewQuery creates a new Query instance.
func NewQuery(opts ...QueryOption) Query {
	q := &query{
		payload: nil,
	}
	for _, opt := range opts {
		opt(q)
	}
	return q
}

// OnboardingPayload returns the onboarding payload of the query.
func (q *query) OnboardingPayload() (OnboardingPayload, bool) {
	if q.payload == nil {
		return nil, false
	}
	return q.payload, true
}

// String returns the string representation of the query.
func (q *query) String() string {
	if q.payload != nil {
		return q.payload.String()
	}
	return ""
}
