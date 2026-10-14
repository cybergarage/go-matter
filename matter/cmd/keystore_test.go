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

package cmd

import (
	"os"
	"testing"

	"github.com/cybergarage/go-matter/matter/keystore"
)

func TestKeyStoreFromEnv(t *testing.T) {
	t.Setenv(KeyStoreEnv, "")
	t.Setenv(KeyStorePassphraseEnv, "")
	os.Unsetenv(KeyStorePassphraseEnv)
	if ks, err := KeyStoreFromEnv(); ks != nil || err != nil {
		t.Fatalf("KeyStoreFromEnv() without the variables = %v, %v; want none", ks, err)
	}

	t.Setenv(KeyStorePassphraseEnv, "secret")
	if _, err := KeyStoreFromEnv(); err == nil {
		t.Fatal("a passphrase without a key store was taken")
	}

	dir := t.TempDir()
	t.Setenv(KeyStoreEnv, dir)
	t.Setenv(KeyStorePassphraseEnv, "secret")
	ks, err := KeyStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	fks, ok := ks.(*keystore.FileKeyStore)
	if !ok || !fks.Encrypted() || fks.Dir() != dir {
		t.Fatalf("KeyStoreFromEnv() = %#v, want an encrypted file key store in %s", ks, dir)
	}
	if _, set := os.LookupEnv(KeyStorePassphraseEnv); set {
		t.Error("the passphrase stayed in the environment")
	}
}
