// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package credentials

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/x509"
	"testing"

	"github.com/cybergarage/go-matter/matter/credentials/chipcert"
)

func TestControllerIdentityIsolatedGenerationAndValidation(t *testing.T) {
	id, err := GenerateControllerIdentity()
	if err != nil {
		t.Fatal("identity generation failed")
	}
	if err := ValidateControllerIdentity(id); err != nil {
		t.Fatal("identity invalid")
	}
	other, err := GenerateControllerIdentity()
	if err != nil {
		t.Fatal("second identity generation failed")
	}
	if id.FabricID == other.FabricID || id.NodeID == other.NodeID {
		t.Fatal("IDs reused")
	}
	// Device-side TLV reconstruction must preserve signed DER, including critical extensions/UTF8 OIDs.
	for _, der := range [][]byte{id.RootCertificate, id.NOC} {
		wire, err := chipcert.DERToTLV(der)
		if err != nil {
			t.Fatal("DER to TLV failed")
		}
		round, err := chipcert.TLVToDER(wire)
		if err != nil {
			t.Fatal("TLV to DER failed")
		}
		cert, err := x509.ParseCertificate(round)
		if err != nil {
			t.Fatal("round-trip parse failed")
		}
		root, _ := x509.ParseCertificate(id.RootCertificate)
		if err := cert.CheckSignatureFrom(root); err != nil {
			t.Fatal("round-trip signature invalid")
		}
	}
	cases := []ControllerIdentity{id, id, id, id, id, id}
	cases[0].FabricID++
	cases[1].NodeID++
	cases[2].PrivateKey = other.PrivateKey
	cases[3].RootPrivateKey = other.RootPrivateKey
	cases[4].IPK = nil
	cases[5].NOC = []byte("invalid")
	for _, bad := range cases {
		if ValidateControllerIdentity(bad) == nil {
			t.Fatal("corrupt identity accepted")
		}
	}
}

// RFC 5280 section 4.2.1.2 method 1 identifies keys; it does not sign certificates.
func TestControllerCertificateIdentifiersAndStrongSignatures(t *testing.T) {
	id, err := GenerateControllerIdentity()
	if err != nil {
		t.Fatal("isolated generation failed")
	}
	root, err := x509.ParseCertificate(id.RootCertificate)
	if err != nil {
		t.Fatal("root parse failed")
	}
	pub := root.PublicKey.(*ecdsa.PublicKey)
	identifier := sha1.Sum(elliptic.Marshal(pub.Curve, pub.X, pub.Y))
	if !bytes.Equal(root.SubjectKeyId, identifier[:]) || !bytes.Equal(root.AuthorityKeyId, identifier[:]) {
		t.Fatal("root key identifier mismatch")
	}
	for _, der := range [][]byte{id.RootCertificate, id.NOC} {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal("certificate parse failed")
		}
		if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			t.Fatal("unexpected certificate signature algorithm")
		}
		if !bytes.Equal(cert.AuthorityKeyId, root.SubjectKeyId) {
			t.Fatal("issuer key identifier mismatch")
		}
		if err := cert.CheckSignatureFrom(root); err != nil {
			t.Fatal("signature verification failed")
		}
	}
}
