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

// Package administratorcommissioning is the client of the Administrator
// Commissioning cluster, by which an administrator of a commissioned node
// opens a commissioning window on it for another administrator to add it
// to another fabric: multi-admin. 11.19. Administrator Commissioning
// Cluster.
package administratorcommissioning

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/protocol/pase"
	"github.com/cybergarage/go-matter/matter/protocol/session"
	"github.com/cybergarage/go-matter/matter/types"
)

// ClusterID is the Administrator Commissioning cluster identifier.
const ClusterID im.ClusterID = 0x003C

// Command IDs. 11.19.8. Commands.
const (
	OpenCommissioningWindowCommandID      im.CommandID = 0x00
	OpenBasicCommissioningWindowCommandID im.CommandID = 0x01
	RevokeCommissioningCommandID          im.CommandID = 0x02
)

// WindowStatusAttributeID is the state of the commissioning window.
// 11.19.7.1. WindowStatus Attribute.
const WindowStatusAttributeID im.AttributeID = 0x0000

// WindowStatus is the state of the commissioning window of a node.
// 11.19.5.1. CommissioningWindowStatusEnum.
type WindowStatus uint8

const (
	// WindowNotOpen: no window is open.
	WindowNotOpen WindowStatus = 0
	// EnhancedWindowOpen: a window opened with OpenCommissioningWindow.
	EnhancedWindowOpen WindowStatus = 1
	// BasicWindowOpen: a window opened with OpenBasicCommissioningWindow.
	BasicWindowOpen WindowStatus = 2
)

// The bounds of a commissioning window's timeout. 11.19.7.
const (
	MinCommissioningTimeout = 3 * time.Minute
	MaxCommissioningTimeout = 15 * time.Minute
)

// DefaultIterations is the PBKDF iteration count of the verifier of a
// window: the smallest allowed, as the reference implementation uses.
const DefaultIterations = crypto.PBKDBFIterationsMin

// The errors of the cluster-specific status codes. 11.19.6.1. StatusCode.
var (
	// ErrBusy: a window is open already, or a commissioning is in
	// progress.
	ErrBusy = errors.New("administratorcommissioning: the node is busy with another commissioning window (Busy)")
	// ErrPAKEParameterError: the node refused the verifier, the salt or
	// the iterations.
	ErrPAKEParameterError = errors.New("administratorcommissioning: the node refused the PAKE parameters (PAKEParameterError)")
	// ErrWindowNotOpen: RevokeCommissioning found no window to close.
	ErrWindowNotOpen = errors.New("administratorcommissioning: no commissioning window is open (WindowNotOpen)")
)

const (
	statusBusy               uint8 = 2
	statusPAKEParameterError uint8 = 3
	statusWindowNotOpen      uint8 = 4
)

// Window is a commissioning window to open on a node with
// OpenCommissioningWindow: a fresh passcode, its verifier and a
// discriminator, with the onboarding codes another administrator adds the
// node with. 5.6.3. Enhanced Commissioning Method.
type Window struct {
	// Passcode is the setup passcode of the window.
	Passcode uint32
	// Discriminator is the 12-bit discriminator the node advertises
	// during the window.
	Discriminator uint16
	// Verifier is what the node is given instead of the passcode.
	Verifier pase.Verifier
	// ManualPairingCode is the 11-digit code of the window.
	ManualPairingCode encoding.PairingCode
	// QRCode is the QR code payload of the window, with the node's
	// VendorID and ProductID and on-network discovery.
	QRCode encoding.QRPayload
}

// NewWindow returns a window with a random passcode, discriminator and
// salt for the node of vendorID and productID. 5.1.7. Generation of the
// Passcode.
func NewWindow(vendorID, productID uint16) (Window, error) {
	passcode, err := randomPasscode()
	if err != nil {
		return Window{}, err
	}
	discriminator := binary.LittleEndian.Uint16(crypto.CryptoTRNG(2)) & 0x0FFF
	verifier, err := pase.NewRandomSaltVerifier(types.Passcode(passcode), DefaultIterations)
	if err != nil {
		return Window{}, fmt.Errorf("administratorcommissioning: verifier: %w", err)
	}
	manual, err := encoding.NewManualPairingCode(discriminator, passcode)
	if err != nil {
		return Window{}, err
	}
	qr, err := encoding.NewQRPayload(vendorID, productID, encoding.DiscoveryCapabilityOnNetwork, discriminator, passcode)
	if err != nil {
		return Window{}, err
	}
	return Window{
		Passcode:          passcode,
		Discriminator:     discriminator,
		Verifier:          verifier,
		ManualPairingCode: manual,
		QRCode:            qr,
	}, nil
}

// randomPasscode draws a passcode uniformly among the valid ones.
func randomPasscode() (uint32, error) {
	for range 64 {
		// 27 bits hold 0..134217727; the values above 99999998 and the
		// trivial ones are drawn again.
		passcode := binary.LittleEndian.Uint32(crypto.CryptoTRNG(4)) & 0x07FFFFFF
		if encoding.ValidatePasscode(passcode) == nil {
			return passcode, nil
		}
	}
	return 0, errors.New("administratorcommissioning: no valid passcode drawn")
}

// OpenCommissioningWindow opens window on the node for timeout, from 3 to
// 15 minutes, in a timed interaction: the node then advertises itself for
// commissioning with the window's discriminator, and accepts PASE with its
// passcode. 11.19.8.1. OpenCommissioningWindow Command.
func OpenCommissioningWindow(sess session.SecureSession, ep im.EndpointID, window Window, timeout time.Duration) error {
	if timeout < MinCommissioningTimeout || MaxCommissioningTimeout < timeout {
		return fmt.Errorf("administratorcommissioning: timeout %v is out of %v..%v", timeout, MinCommissioningTimeout, MaxCommissioningTimeout)
	}
	if err := window.Verifier.Validate(); err != nil {
		return fmt.Errorf("administratorcommissioning: %w", err)
	}
	fields, err := buildOpenCommissioningWindowFields(window, timeout)
	if err != nil {
		return err
	}
	resp, err := im.TimedInvoke(sess, ep, ClusterID, OpenCommissioningWindowCommandID, fields, 0)
	if err != nil {
		return fmt.Errorf("administratorcommissioning: OpenCommissioningWindow: %w", err)
	}
	return statusError("OpenCommissioningWindow", resp)
}

// OpenBasicCommissioningWindow opens a window with the node's own setup
// code for timeout, from 3 to 15 minutes, on a node which supports it.
// 11.19.8.2. OpenBasicCommissioningWindow Command.
func OpenBasicCommissioningWindow(sess session.SecureSession, ep im.EndpointID, timeout time.Duration) error {
	if timeout < MinCommissioningTimeout || MaxCommissioningTimeout < timeout {
		return fmt.Errorf("administratorcommissioning: timeout %v is out of %v..%v", timeout, MinCommissioningTimeout, MaxCommissioningTimeout)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned2(tlv.NewContextTag(0), uint16(timeout/time.Second))
	if err := enc.EndContainer(); err != nil {
		return err
	}
	resp, err := im.TimedInvoke(sess, ep, ClusterID, OpenBasicCommissioningWindowCommandID, enc.Bytes(), 0)
	if err != nil {
		return fmt.Errorf("administratorcommissioning: OpenBasicCommissioningWindow: %w", err)
	}
	return statusError("OpenBasicCommissioningWindow", resp)
}

// RevokeCommissioning closes the open commissioning window of the node,
// and ends a commissioning in progress through it. 11.19.8.3.
// RevokeCommissioning Command.
func RevokeCommissioning(sess session.SecureSession, ep im.EndpointID) error {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.EndContainer(); err != nil {
		return err
	}
	resp, err := im.TimedInvoke(sess, ep, ClusterID, RevokeCommissioningCommandID, enc.Bytes(), 0)
	if err != nil {
		return fmt.Errorf("administratorcommissioning: RevokeCommissioning: %w", err)
	}
	return statusError("RevokeCommissioning", resp)
}

// ReadWindowStatus reads the state of the node's commissioning window.
func ReadWindowStatus(sess session.SecureSession, ep im.EndpointID) (WindowStatus, error) {
	v, err := im.ReadUnsigned1Attribute(sess, ep, ClusterID, WindowStatusAttributeID)
	if err != nil {
		return 0, fmt.Errorf("administratorcommissioning: WindowStatus: %w", err)
	}
	return WindowStatus(v), nil
}

// buildOpenCommissioningWindowFields encodes the fields of
// OpenCommissioningWindow: CommissioningTimeout, PAKEPasscodeVerifier (w0
// followed by L), Discriminator, Iterations and Salt. 11.19.8.1.
func buildOpenCommissioningWindowFields(window Window, timeout time.Duration) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned2(tlv.NewContextTag(0), uint16(timeout/time.Second))
	if err := enc.PutOctet(tlv.NewContextTag(1), window.Verifier.Bytes()); err != nil {
		return nil, err
	}
	enc.PutUnsigned2(tlv.NewContextTag(2), window.Discriminator)
	enc.PutUnsigned4(tlv.NewContextTag(3), uint32(window.Verifier.Iterations))
	if err := enc.PutOctet(tlv.NewContextTag(4), window.Verifier.Salt); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// statusError returns the error of the status of resp, if any.
func statusError(command string, resp *im.InvokeResponse) error {
	if resp.IsSuccess() {
		return nil
	}
	switch resp.Status.ClusterStatus {
	case statusBusy:
		return ErrBusy
	case statusPAKEParameterError:
		return ErrPAKEParameterError
	case statusWindowNotOpen:
		return ErrWindowNotOpen
	}
	return fmt.Errorf("administratorcommissioning: %s failed: IM status 0x%02X, cluster status 0x%02X", command, resp.Status.IMStatus, resp.Status.ClusterStatus)
}
