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

package mattertest

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-matter/matter/cluster/onoff"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/credentials/testcreds"
	"github.com/cybergarage/go-matter/matter/encoding"
	"github.com/cybergarage/go-matter/matter/keystore"
	"github.com/cybergarage/go-matter/matter/store"
)

const keyStoreLightDiscriminator = 0x0ABF

// TestCommissionWithAKeyStore creates a fabric whose root and operational
// keys live only in an encrypted key store, commissions a matter/device
// light with it, which signs the light's NOC with the root key, and
// connects over CASE, which signs Sigma3 with the operational key. The
// commissioner's store holds no private key.
func TestCommissionWithAKeyStore(t *testing.T) {
	if testing.Short() {
		t.Skip("uses mDNS on the network; skipped with -short")
	}
	storeDir := t.TempDir()
	keyDir := filepath.Join(t.TempDir(), "keys")
	passphrase := []byte("test passphrase")
	ks, err := keystore.NewFileKeyStore(keyDir, keystore.WithPassphrase(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	root, err := ks.Generate(matter.RootKeyName)
	if err != nil {
		t.Fatal(err)
	}
	operational, err := ks.Generate(matter.OperationalKeyName)
	if err != nil {
		t.Fatal(err)
	}
	id, err := credentials.GenerateControllerIdentityWithSigners(root, operational)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.NewStore(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateFabric(st, store.FabricRecord{
		FabricID: id.FabricID, AdminNodeID: id.NodeID, AdminVendorID: uint16(defaultAdminVendorID),
		RootCertificate: id.RootCertificate, NOC: id.NOC, IPK: id.IPK, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	// The key store is opened again, as by another process.
	reopened, err := keystore.NewFileKeyStore(keyDir, keystore.WithPassphrase(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	cmr := matter.NewCommissioner(
		matter.WithCommissionerCentral(noBLECentral{}),
		matter.WithCommissionerStoreDir(storeDir),
		matter.WithCommissionerKeyStore(reopened),
	)
	if err := cmr.Start(); err != nil {
		t.Skipf("the commissioner cannot start here: %v", err)
	}
	defer cmr.Stop()

	dev, _ := newTestLight(t, store.NewMemDeviceStore(), keyStoreLightDiscriminator)
	if err := dev.Start(); err != nil {
		t.Skipf("the device cannot advertise here: %v", err)
	}
	defer dev.Stop()
	mpc := buildManualPairingCodeForTest(t, keyStoreLightDiscriminator, deviceCommissioningPasscode, testcreds.VendorID, testcreds.ProductID)
	pairingCode, err := encoding.NewPairingCodeFromString(mpc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), matter.DefaultCommissioningTimeout)
	defer cancel()
	cme, err := cmr.Commission(ctx, pairingCode)
	if err != nil {
		t.Fatalf("Commission() error = %v", err)
	}
	nodeID, _ := cme.NodeID()

	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelConnect()
	node, err := cmr.Connect(connectCtx, uint64(nodeID))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer node.Close()
	if _, err := onoff.OnOff(node.Session(), 1); err != nil {
		t.Fatalf("read OnOff: %v", err)
	}

	// No private key reached the commissioner's store.
	err = filepath.WalkDir(storeDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte("PrivateKey")) || bytes.Contains(b, []byte("privateKey")) {
			t.Errorf("%s holds a private key", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
