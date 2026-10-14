// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package credentials

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"time"

	"github.com/cybergarage/go-matter/matter/types"
)

// ControllerIdentity contains secret material. Never format or log it.
// 6.5. Node Operational Credentials. This minimal CA has no intermediate.
//
// A key is either its PKCS#8 bytes (RootPrivateKey, PrivateKey) or, when
// it is kept in a key store, an HSM or a KMS, a signer (RootSigner,
// Signer), which takes the place of the bytes.
type ControllerIdentity struct {
	FabricID, NodeID                                      uint64
	RootCertificate, RootPrivateKey, NOC, PrivateKey, IPK []byte
	RootSigner, Signer                                    crypto.Signer
}

// RandomOperationalID uses the full operational ID range and propagates entropy failures.
func RandomOperationalID() (uint64, error) {
	for {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, errors.New("cannot obtain identity entropy")
		}
		n := binary.BigEndian.Uint64(b[:])
		if types.NodeID(n).IsOperational() {
			return n, nil
		}
	}
}

// GenerateControllerIdentity creates a new local fabric only when called explicitly.
// It performs no persistence, discovery or device operation.
func GenerateControllerIdentity() (ControllerIdentity, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ControllerIdentity{}, errors.New("cannot create root key")
	}
	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return ControllerIdentity{}, errors.New("cannot create controller key")
	}
	out, err := generateControllerIdentity(rootKey, nodeKey)
	if err != nil {
		return ControllerIdentity{}, err
	}
	out.RootPrivateKey, err = x509.MarshalPKCS8PrivateKey(rootKey)
	if err != nil {
		return ControllerIdentity{}, err
	}
	out.PrivateKey, err = x509.MarshalPKCS8PrivateKey(nodeKey)
	if err != nil {
		return ControllerIdentity{}, err
	}
	out.RootSigner, out.Signer = nil, nil
	return out, ValidateControllerIdentity(out)
}

// GenerateControllerIdentityWithSigners is GenerateControllerIdentity with
// the root and the controller's operational keys made beforehand where
// they are kept, such as in a key store: the identity holds the signers,
// and no key bytes.
func GenerateControllerIdentityWithSigners(rootKey, nodeKey crypto.Signer) (ControllerIdentity, error) {
	if rootKey == nil || nodeKey == nil {
		return ControllerIdentity{}, errors.New("a root and a controller signer are required")
	}
	out, err := generateControllerIdentity(rootKey, nodeKey)
	if err != nil {
		return ControllerIdentity{}, err
	}
	return out, ValidateControllerIdentity(out)
}

func generateControllerIdentity(rootKey, nodeKey crypto.Signer) (ControllerIdentity, error) {
	var out ControllerIdentity
	var err error
	rootPub, ok := rootKey.Public().(*ecdsa.PublicKey)
	if !ok || rootPub.Curve != elliptic.P256() {
		return out, errors.New("the root key is not a P-256 key")
	}
	if pub, ok := nodeKey.Public().(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		return out, errors.New("the controller key is not a P-256 key")
	}
	out.FabricID, err = RandomOperationalID()
	if err != nil {
		return out, err
	}
	out.NodeID, err = RandomOperationalID()
	if err != nil {
		return out, err
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return out, errors.New("cannot create certificate serial")
	}
	rcacID, err := RandomOperationalID()
	if err != nil {
		return out, err
	}
	// The key identifier of RFC 5280 4.2.1.2 method 1, which Matter
	// certificates use; SHA-1 names the key here, it secures nothing.
	skid := sha1.Sum(elliptic.Marshal(rootPub.Curve, rootPub.X, rootPub.Y)) // NOSONAR
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{utf8Attr(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4}, uint64ToHexRDNValue(rcacID))}},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true,
		SubjectKeyId: skid[:], AuthorityKeyId: skid[:],
	}
	out.RootCertificate, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, rootPub, rootKey)
	if err != nil {
		return ControllerIdentity{}, errors.New("cannot create root certificate")
	}
	out.RootSigner, out.Signer = rootKey, nodeKey
	ca, err := NewCertificateAuthorityWithSigner(out.RootCertificate, rootKey, out.FabricID)
	if err != nil {
		return ControllerIdentity{}, err
	}
	out.NOC, err = ca.IssueNOC(&x509.CertificateRequest{PublicKey: nodeKey.Public()}, out.NodeID)
	if err != nil {
		return ControllerIdentity{}, err
	}
	out.IPK = make([]byte, 16)
	if _, err := rand.Read(out.IPK); err != nil {
		return ControllerIdentity{}, errors.New("cannot create identity protection key")
	}
	return out, nil
}

// ValidateControllerIdentity checks restored material before any network operation.
// Errors identify the problem, never echo keys, certificates or input values.
func ValidateControllerIdentity(id ControllerIdentity) error {
	if id.FabricID == 0 || !types.NodeID(id.NodeID).IsOperational() || len(id.IPK) != 16 {
		return errors.New("invalid fabric/controller ID or IPK length")
	}
	var ca *CertificateAuthority
	var err error
	if id.RootSigner != nil {
		ca, err = NewCertificateAuthorityWithSigner(id.RootCertificate, id.RootSigner, id.FabricID)
	} else {
		ca, err = NewCertificateAuthority(id.RootCertificate, id.RootPrivateKey, id.FabricID)
	}
	if err != nil {
		return errors.New("invalid root certificate/key")
	}
	rootPub, ok := ca.rootKey.Public().(*ecdsa.PublicKey)
	if !ok || rootPub.Curve != elliptic.P256() || !ca.rootCert.IsCA || ca.rootCert.KeyUsage&x509.KeyUsageCertSign == 0 || ca.rootCert.CheckSignatureFrom(ca.rootCert) != nil {
		return errors.New("invalid P-256 root CA")
	}
	der, err := certificateDERBytes(id.NOC)
	if err != nil {
		return errors.New("invalid controller certificate")
	}
	noc, err := x509.ParseCertificate(der)
	if err != nil {
		return errors.New("invalid controller certificate")
	}
	var keyPub *ecdsa.PublicKey
	if id.Signer != nil {
		keyPub, _ = id.Signer.Public().(*ecdsa.PublicKey)
	} else if key, err := parsePrivateKey(id.PrivateKey); err == nil {
		keyPub = &key.PublicKey
	}
	if keyPub == nil || keyPub.Curve != elliptic.P256() {
		return errors.New("invalid controller key")
	}
	pub, ok := noc.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(keyPub) {
		return errors.New("controller key/certificate mismatch")
	}
	var nodeOK, fabricOK bool
	for _, a := range noc.Subject.Names {
		if a.Type.Equal(oidMatterNodeID) {
			nodeOK = a.Value == uint64ToHexRDNValue(id.NodeID)
		}
		if a.Type.Equal(oidMatterFabricID) {
			fabricOK = a.Value == uint64ToHexRDNValue(id.FabricID)
		}
	}
	if !nodeOK || !fabricOK {
		return errors.New("controller certificate identity mismatch")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.rootCert)
	if _, err := noc.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return errors.New("invalid controller certificate chain or validity")
	}
	if _, err := noc.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return errors.New("controller certificate lacks server authentication usage")
	}
	if noc.IsCA || noc.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("invalid controller certificate usage")
	}
	return nil
}
