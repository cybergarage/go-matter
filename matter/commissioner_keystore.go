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

package matter

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/keystore"
	"github.com/cybergarage/go-matter/matter/store"
)

// The names of the fabric's keys in a Commissioner's key store.
const (
	// RootKeyName names the root CA key, which signs the NOCs the
	// commissioner issues (6.5. Node Operational Credentials).
	RootKeyName = "root"
	// OperationalKeyName names the key of the commissioner's own NOC, which
	// signs its CASE Sigma3.
	OperationalKeyName = "operational"
)

// WithCommissionerKeyStore keeps the fabric's private keys in ks, under
// RootKeyName and OperationalKeyName, instead of in the store's fabric
// record. Start takes a fabric's keys from ks, and moves the keys an older
// fabric record holds into ks when ks is a keystore.Importer, removing them
// from the record once ks has them. Without a key store, the keys stay in
// the fabric record, as before.
func WithCommissionerKeyStore(ks keystore.KeyStore) CommissionerOption {
	return func(cmr *commissioner) {
		cmr.keyStore = ks
	}
}

// fabricKeys returns the signers of rec's root and operational keys from
// the key store, moving the keys rec holds into it. A key moved, or which
// the key store already has, is removed from rec, and moved reports
// whether one was. A key which stays in rec, as when the key store cannot
// import it, gets no signer: the record's bytes are used.
func (cmr *commissioner) fabricKeys(rec *store.FabricRecord) (root, operational crypto.Signer, moved bool, err error) { // nolint: nonamedreturns
	if cmr.keyStore == nil {
		return nil, nil, false, nil
	}
	root, movedRoot, err := cmr.fabricKey(RootKeyName, rec.RootCertificate, &rec.RootPrivateKey)
	if err != nil {
		return nil, nil, false, err
	}
	operational, movedOperational, err := cmr.fabricKey(OperationalKeyName, rec.NOC, &rec.PrivateKey)
	if err != nil {
		return nil, nil, false, err
	}
	return root, operational, movedRoot || movedOperational, nil
}

// fabricKey returns the key store's key named name, which must be the key
// of certBytes, after moving *keyBytes into the key store when it does not
// have the key yet.
func (cmr *commissioner) fabricKey(name string, certBytes []byte, keyBytes *[]byte) (crypto.Signer, bool, error) {
	want, err := certificatePublicKey(certBytes)
	if err != nil {
		return nil, false, fmt.Errorf("commissioner: the fabric's %s certificate: %w", name, err)
	}
	signer, err := cmr.keyStore.Signer(name)
	switch {
	case err == nil:
		if !want.Equal(signer.Public()) {
			return nil, false, fmt.Errorf("commissioner: the key store's %s key is not the key of the fabric's certificate", name)
		}
		moved := len(*keyBytes) != 0
		*keyBytes = nil
		return signer, moved, nil
	case !errors.Is(err, keystore.ErrKeyNotFound):
		return nil, false, fmt.Errorf("commissioner: key store: %w", err)
	case len(*keyBytes) == 0:
		log.Warnf("commissioner: the key store has no %s key, and the fabric record none either", name)
		return nil, false, nil
	}
	importer, ok := cmr.keyStore.(keystore.Importer)
	if !ok {
		log.Warnf("commissioner: the key store cannot import the fabric's %s key; it stays in the fabric record", name)
		return nil, false, nil
	}
	key, err := credentials.ParsePrivateKey(*keyBytes)
	if err != nil {
		return nil, false, fmt.Errorf("commissioner: the fabric's %s key: %w", name, err)
	}
	if !want.Equal(&key.PublicKey) {
		return nil, false, fmt.Errorf("commissioner: the fabric's %s key is not the key of its certificate", name)
	}
	if err := importer.Import(name, key); err != nil {
		return nil, false, fmt.Errorf("commissioner: move the fabric's %s key into the key store: %w", name, err)
	}
	log.Infof("commissioner: moved the fabric's %s key into the key store", name)
	*keyBytes = nil
	return key, true, nil
}

func certificatePublicKey(b []byte) (*ecdsa.PublicKey, error) {
	if block, _ := pem.Decode(b); block != nil {
		b = block.Bytes
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	return pub, nil
}
