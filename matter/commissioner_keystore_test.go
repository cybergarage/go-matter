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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/keystore"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/store"
)

func testFabricRecord(t *testing.T) (store.FabricRecord, credentials.ControllerIdentity) {
	t.Helper()
	id, err := credentials.GenerateControllerIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return store.FabricRecord{
		FabricID: id.FabricID, AdminNodeID: id.NodeID, AdminVendorID: 0xFFF1,
		RootCertificate: id.RootCertificate, RootPrivateKey: id.RootPrivateKey,
		NOC: id.NOC, PrivateKey: id.PrivateKey, IPK: id.IPK, UpdatedAt: time.Now().UTC(),
	}, id
}

func startWithKeyStore(t *testing.T, st store.Store, ks keystore.KeyStore) (*commissioner, error) {
	t.Helper()
	cmr, ok := NewCommissioner(
		WithCommissionerCentral(noScanCentral{}),
		WithCommissionerDiscoverer(&stubDiscoverer{}),
		WithCommissionerStore(st),
		WithCommissionerKeyStore(ks),
	).(*commissioner)
	if !ok {
		t.Fatal("NewCommissioner() is not a *commissioner")
	}
	err := cmr.Start()
	t.Cleanup(func() { _ = cmr.Stop() })
	return cmr, err
}

// requireUsableIdentity checks that the commissioner issues NOCs and runs
// CASE with its administrator config.
func requireUsableIdentity(t *testing.T, cmr *commissioner) {
	t.Helper()
	ca, err := loadCertificateAuthority(cmr.adminConfig)
	if err != nil {
		t.Fatalf("loadCertificateAuthority() error = %v", err)
	}
	device, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.IssueNOC(&x509.CertificateRequest{PublicKey: &device.PublicKey}, 0x1234); err != nil {
		t.Fatalf("IssueNOC() error = %v", err)
	}
	if _, err := caseprotocol.LoadAdministratorMetadata(cmr.adminConfig); err != nil {
		t.Fatalf("LoadAdministratorMetadata() error = %v", err)
	}
}

func TestStartMovesTheFabricKeysIntoTheKeyStore(t *testing.T) {
	st := store.NewMemStore()
	rec, id := testFabricRecord(t)
	if err := st.SaveFabric(rec); err != nil {
		t.Fatal(err)
	}
	ks := keystore.NewMemKeyStore()
	cmr, err := startWithKeyStore(t, st, ks)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	saved, _, err := st.LoadFabric()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.RootPrivateKey) != 0 || len(saved.PrivateKey) != 0 {
		t.Fatal("the fabric record still holds the keys moved into the key store")
	}
	root, err := ks.Signer(RootKeyName)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := credentials.ParsePrivateKey(id.RootPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if !rootKey.PublicKey.Equal(root.Public()) {
		t.Fatal("the key store's root key is not the fabric's")
	}
	if _, err := ks.Signer(OperationalKeyName); err != nil {
		t.Fatal(err)
	}
	if _, ok := cmr.adminConfig.RootSigner(); !ok {
		t.Fatal("the administrator config has no root signer")
	}
	requireUsableIdentity(t, cmr)

	// A second start takes the keys from the key store alone.
	again, err := startWithKeyStore(t, st, ks)
	if err != nil {
		t.Fatalf("second Start() error = %v", err)
	}
	if _, ok := again.adminConfig.RootPrivateKey(); ok {
		t.Error("the administrator config holds root key bytes")
	}
	requireUsableIdentity(t, again)
}

// noImportKeyStore is a key store which cannot import, as an HSM may not.
type noImportKeyStore struct{ keystore.KeyStore }

func TestStartKeepsTheKeysAKeyStoreCannotTake(t *testing.T) {
	st := store.NewMemStore()
	rec, _ := testFabricRecord(t)
	if err := st.SaveFabric(rec); err != nil {
		t.Fatal(err)
	}
	cmr, err := startWithKeyStore(t, st, noImportKeyStore{keystore.NewMemKeyStore()})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	saved, _, _ := st.LoadFabric()
	if len(saved.RootPrivateKey) == 0 || len(saved.PrivateKey) == 0 {
		t.Fatal("keys the key store could not take were removed from the record")
	}
	requireUsableIdentity(t, cmr)
}

func TestStartRefusesAKeyStoreWithOtherKeys(t *testing.T) {
	st := store.NewMemStore()
	rec, _ := testFabricRecord(t)
	if err := st.SaveFabric(rec); err != nil {
		t.Fatal(err)
	}
	ks := keystore.NewMemKeyStore()
	if _, err := ks.Generate(RootKeyName); err != nil {
		t.Fatal(err)
	}
	if _, err := startWithKeyStore(t, st, ks); err == nil {
		t.Fatal("Start() took a key store whose root key is not the fabric's")
	}
	saved, _, _ := st.LoadFabric()
	if len(saved.RootPrivateKey) == 0 {
		t.Fatal("the record lost its root key")
	}
}

// failingKeyStore fails as a locked HSM or a wrong passphrase does.
type failingKeyStore struct{ keystore.KeyStore }

var errLocked = errors.New("locked")

func (failingKeyStore) Signer(string) (crypto.Signer, error) { return nil, errLocked }

func TestStartFailsWhenTheKeyStoreFails(t *testing.T) {
	st := store.NewMemStore()
	rec, _ := testFabricRecord(t)
	if err := st.SaveFabric(rec); err != nil {
		t.Fatal(err)
	}
	if _, err := startWithKeyStore(t, st, failingKeyStore{keystore.NewMemKeyStore()}); !errors.Is(err, errLocked) {
		t.Fatalf("Start() error = %v, want the key store's", err)
	}
}

// opaqueSigner hides its key, as an HSM does.
type opaqueSigner struct{ key *ecdsa.PrivateKey }

func (s opaqueSigner) Public() crypto.PublicKey { return &s.key.PublicKey }
func (s opaqueSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(r, digest, opts)
}

func TestStaticKeyStoreServesAFabric(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root, node := opaqueSigner{rootKey}, opaqueSigner{nodeKey}
	id, err := credentials.GenerateControllerIdentityWithSigners(root, node)
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemStore()
	if err := st.SaveFabric(store.FabricRecord{
		FabricID: id.FabricID, AdminNodeID: id.NodeID, AdminVendorID: 0xFFF1,
		RootCertificate: id.RootCertificate, NOC: id.NOC, IPK: id.IPK, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	ks, err := keystore.NewStaticKeyStore(map[string]crypto.Signer{RootKeyName: root, OperationalKeyName: node})
	if err != nil {
		t.Fatal(err)
	}
	cmr, err := startWithKeyStore(t, st, ks)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	requireUsableIdentity(t, cmr)
}
