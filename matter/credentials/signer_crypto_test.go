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

package credentials

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"sync/atomic"
	"testing"
)

// opaqueSigner is a crypto.Signer which does not give its key out, as an
// HSM or a KMS key does.
type opaqueSigner struct {
	key   *ecdsa.PrivateKey
	signs atomic.Int32
	// wrong signs with another key.
	wrong *ecdsa.PrivateKey
}

func newOpaqueSigner(t *testing.T) *opaqueSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &opaqueSigner{key: key}
}

func (s *opaqueSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s *opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.signs.Add(1)
	if s.wrong != nil {
		return s.wrong.Sign(r, digest, opts)
	}
	return s.key.Sign(r, digest, opts)
}

func TestNewSignerSignsWithAnOpaqueKey(t *testing.T) {
	cs := newOpaqueSigner(t)
	signer, err := NewSigner(cs)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("Sigma3 TBS data")
	sig, err := signer.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != rawSignatureLen || cs.signs.Load() != 1 {
		t.Fatalf("signature of %d bytes after %d signs, want %d bytes from the opaque key", len(sig), cs.signs.Load(), rawSignatureLen)
	}
	if err := VerifySignature(&cs.key.PublicKey, msg, sig); err != nil {
		t.Fatalf("the raw signature does not verify: %v", err)
	}

	cs.wrong = newOpaqueSigner(t).key
	if _, err := signer.Sign(msg); err == nil {
		t.Error("a signature by another key was not caught")
	}
}

func TestNewSignerRejectsOtherKeys(t *testing.T) {
	if _, err := NewSigner(nil); err == nil {
		t.Error("NewSigner(nil) succeeded")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigner(p384); err == nil {
		t.Error("NewSigner() took a P-384 key")
	}
}

func TestControllerIdentityWithSigners(t *testing.T) {
	root, node := newOpaqueSigner(t), newOpaqueSigner(t)
	id, err := GenerateControllerIdentityWithSigners(root, node)
	if err != nil {
		t.Fatal(err)
	}
	if len(id.RootPrivateKey) != 0 || len(id.PrivateKey) != 0 {
		t.Fatal("an identity with signers holds key bytes")
	}
	if root.signs.Load() == 0 {
		t.Fatal("the root signer did not sign the certificates")
	}
	if err := ValidateControllerIdentity(id); err != nil {
		t.Fatalf("ValidateControllerIdentity() error = %v", err)
	}
	swapped := id
	swapped.Signer = newOpaqueSigner(t)
	if err := ValidateControllerIdentity(swapped); err == nil {
		t.Error("an identity whose signer does not match its NOC is valid")
	}

	ca, err := NewCertificateAuthorityWithSigner(id.RootCertificate, root, id.FabricID)
	if err != nil {
		t.Fatal(err)
	}
	device := newOpaqueSigner(t)
	der, err := ca.IssueNOC(&x509.CertificateRequest{PublicKey: device.Public()}, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	noc, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(id.RootCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := noc.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("the NOC is not signed by the root: %v", err)
	}
	if _, err := NewCertificateAuthorityWithSigner(id.RootCertificate, node, id.FabricID); err == nil {
		t.Error("a CA took a signer which is not the root's")
	}
	if _, err := GenerateControllerIdentityWithSigners(root, nil); err == nil {
		t.Error("an identity was generated without a controller signer")
	}
}
