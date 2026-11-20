// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

package im

import (
	"context"

	"github.com/cybergarage/go-matter/matter/encoding/message"
)

// WithContext returns sess bound to ctx, for the functions of this package
// and of the cluster packages which take a session: a request made over the
// returned session is not sent once ctx is done, and its wait for the
// response ends when ctx is done, with ctx.Err(). The wait is ended at once
// over a session an ExchangeMux reads, such as the session of a Node;
// over another session, ctx is checked before the wait only.
func WithContext(ctx context.Context, sess SecureSession) SecureSession {
	return &contextSession{SecureSession: sess, ctx: ctx}
}

type contextSession struct {
	SecureSession
	ctx context.Context
}

// exchangeContextReceiver is a session which hands out the messages of one
// exchange until a context is done, such as an ExchangeMux.
type exchangeContextReceiver interface {
	ReceiveExchangeContext(ctx context.Context, exchange message.ExchangeID) ([]byte, error)
}

func (s *contextSession) Transmit(payload []byte) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	return s.SecureSession.Transmit(payload)
}

func (s *contextSession) NewExchangeID() message.ExchangeID {
	return newExchangeID(s.SecureSession)
}

func (s *contextSession) ReceiveExchange(exchange message.ExchangeID) ([]byte, error) {
	if r, ok := s.SecureSession.(exchangeContextReceiver); ok {
		return r.ReceiveExchangeContext(s.ctx, exchange)
	}
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	return receiveExchangeResponse(s.SecureSession, exchange)
}

// Unwrap returns the session ctx is bound to, so that the session package's
// helpers, such as session.PeerMRPParameters, see through it.
func (s *contextSession) Unwrap() SecureSession {
	return s.SecureSession
}
