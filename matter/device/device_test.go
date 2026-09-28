// Copyright (C) 2026 The go-matter Authors. All rights reserved.
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

package device

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
	"github.com/cybergarage/go-matter/matter/protocol/pase/pbkdf"
	"github.com/cybergarage/go-matter/matter/types"
)

const testPasscode = types.Passcode(20202021)

type recordingAdvertiser struct {
	mu        sync.Mutex
	published []CommissionableService
	withdrawn int
}

func (a *recordingAdvertiser) AdvertiseCommissionable(svc CommissionableService) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.published = append(a.published, svc)
	return nil
}

func (a *recordingAdvertiser) Withdraw() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.withdrawn++
	return nil
}

// udpClient is a commissioner's transport to the device.
type udpClient struct {
	conn *net.UDPConn
}

func dialDevice(t *testing.T, d *Device) *udpClient {
	t.Helper()
	addr, ok := d.Addr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("Addr() = %v, want a UDP address", d.Addr())
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &udpClient{conn: conn}
}

func (c *udpClient) Transmit(_ context.Context, b []byte) error {
	_, err := c.conn.Write(b)
	return err
}

func (c *udpClient) Receive(ctx context.Context) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetReadDeadline(deadline)
	}
	buf := make([]byte, maxMessageSize)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func startTestDevice(t *testing.T, opts ...Option) (*Device, *recordingAdvertiser, chan *Session) {
	t.Helper()
	adv := &recordingAdvertiser{}
	sessions := make(chan *Session, 4)
	d, err := New(append([]Option{
		WithPasscode(testPasscode),
		WithAddress("127.0.0.1:0"),
		WithDiscriminator(3840),
		WithVendorID(0xFFF1),
		WithProductID(0x8001),
		WithAdvertiser(adv),
		WithSessionHandler(func(s *Session) { sessions <- s }),
	}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Stop() })
	return d, adv, sessions
}

func TestDeviceCommissionablePASEOverUDP(t *testing.T) {
	d, adv, sessions := startTestDevice(t)

	// The advertised service carries the port the device really listens on.
	adv.mu.Lock()
	if len(adv.published) != 1 {
		t.Fatalf("advertised %d times, want 1", len(adv.published))
	}
	svc := adv.published[0]
	adv.mu.Unlock()
	if port := d.Addr().(*net.UDPAddr).Port; svc.Port != port {
		t.Fatalf("advertised port %d, device listens on %d", svc.Port, port)
	}
	if svc.Discriminator != 3840 || svc.VendorID != 0xFFF1 || svc.ProductID != 0x8001 {
		t.Fatalf("advertised %+v, want the configured discriminator, vendor and product", svc)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := dialDevice(t, d)
	keys, err := pase.NewInitiator(client, testPasscode).EstablishSession(ctx)
	if err != nil {
		t.Fatalf("Initiator.EstablishSession() error = %v", err)
	}

	var sess *Session
	select {
	case sess = <-sessions:
	case <-ctx.Done():
		t.Fatal("the session handler was not called")
	}
	if !bytes.Equal(sess.Keys().I2RKey(), keys.I2RKey()) || !bytes.Equal(sess.Keys().R2IKey(), keys.R2IKey()) {
		t.Fatal("the device and the commissioner derived different session keys")
	}
	if sess.Keys().ResponderSessionID() != keys.ResponderSessionID() {
		t.Fatalf("responder session ID: device %d, commissioner %d", sess.Keys().ResponderSessionID(), keys.ResponderSessionID())
	}

	// A message the commissioner sends on the new session reaches the
	// session's transport.
	secured := message.NewMessage(
		message.WithMessageFrameHeader(message.NewHeader(
			message.WithHeaderSessionID(keys.ResponderSessionID()),
			message.WithHeaderMessageCounter(message.NewMessageCounter()),
		)),
		message.WithMessagePayload([]byte("ciphertext")),
	)
	wire, err := secured.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Transmit(ctx, wire); err != nil {
		t.Fatal(err)
	}
	got, err := sess.Transport().Receive(ctx)
	if err != nil {
		t.Fatalf("session Transport().Receive() error = %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatal("the session transport received a different message")
	}

	if err := d.Stop(); err != nil {
		t.Fatal(err)
	}
	adv.mu.Lock()
	defer adv.mu.Unlock()
	if adv.withdrawn != 1 {
		t.Fatalf("Withdraw called %d times, want 1", adv.withdrawn)
	}
}

func TestDeviceRecoversFromWrongPasscode(t *testing.T) {
	d, _, sessions := startTestDevice(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := pase.NewInitiator(dialDevice(t, d), testPasscode+1).EstablishSession(ctx)
	if !errors.Is(err, pase.ErrPASEVerification) {
		t.Fatalf("EstablishSession() with a wrong passcode error = %v, want ErrPASEVerification", err)
	}
	// The failed attempt must not hold the device's single PASE slot. The
	// device may still be finishing it when the next request arrives, and
	// this initiator does not retransmit, so retry as a commissioner would.
	var lastErr error
	for range 5 {
		attempt, cancelAttempt := context.WithTimeout(ctx, time.Second)
		_, lastErr = pase.NewInitiator(dialDevice(t, d), testPasscode).EstablishSession(attempt)
		cancelAttempt()
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		t.Fatalf("EstablishSession() after a failed attempt error = %v", lastErr)
	}
	select {
	case <-sessions:
	case <-ctx.Done():
		t.Fatal("the session handler was not called")
	}
}

func TestDeviceIgnoresSecondCommissionerDuringPASE(t *testing.T) {
	d, _, _ := startTestDevice(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The first commissioner opens an exchange and stalls after its
	// PBKDFParamRequest.
	first := dialDevice(t, d)
	req, err := pbkdfParamRequestBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Transmit(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Receive(ctx); err != nil {
		t.Fatalf("first commissioner got no PBKDFParamResponse: %v", err)
	}

	// A second one is not answered while that exchange is open.
	second := dialDevice(t, d)
	if err := second.Transmit(ctx, req); err != nil {
		t.Fatal(err)
	}
	short, cancelShort := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancelShort()
	if _, err := second.Receive(short); err == nil {
		t.Fatal("the device answered a second commissioner during an open PASE exchange")
	}
}

func TestNewRequiresVerifier(t *testing.T) {
	if _, err := New(); !errors.Is(err, ErrNoVerifier) {
		t.Fatalf("New() error = %v, want ErrNoVerifier", err)
	}
	if _, err := New(WithPasscode(testPasscode), WithDiscriminator(0x1000)); err == nil {
		t.Fatal("New() with a 13-bit discriminator = nil error, want an error")
	}
	if _, err := New(WithVerifier(pase.Verifier{})); err == nil {
		t.Fatal("New() with an empty verifier = nil error, want an error")
	}
}

func pbkdfParamRequestBytes() ([]byte, error) {
	req, err := pbkdf.NewParamRequestMessage()
	if err != nil {
		return nil, err
	}
	return req.Bytes()
}
