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
	"fmt"
	"os"

	"github.com/cybergarage/go-matter/matter/keystore"
)

// The environment variables which set matterctl's key store. They are
// read before the command line, as the commissioner starts with them, and
// the passphrase is taken only from the environment, so that it is kept
// out of the shell history and the process list.
const (
	// KeyStoreEnv names the directory of the key store which keeps the
	// fabric's private keys instead of the commissioner's store.
	KeyStoreEnv = "MATTER_CTL_KEY_STORE"
	// KeyStorePassphraseEnv holds the passphrase the key store encrypts
	// the keys with; without it, the keys are kept unencrypted, readable
	// by their owner only.
	KeyStorePassphraseEnv = "MATTER_CTL_KEY_STORE_PASSPHRASE" // nolint: gosec // the name of the variable, not a secret
)

// KeyStoreFromEnv opens the key store KeyStoreEnv names, encrypted with
// KeyStorePassphraseEnv when it is set, and removes the passphrase from
// the environment of the process. It returns nil when KeyStoreEnv is not
// set: the keys stay in the commissioner's store.
func KeyStoreFromEnv() (keystore.KeyStore, error) {
	passphrase, hasPassphrase := os.LookupEnv(KeyStorePassphraseEnv)
	_ = os.Unsetenv(KeyStorePassphraseEnv)
	dir := os.Getenv(KeyStoreEnv)
	if dir == "" {
		if hasPassphrase {
			return nil, fmt.Errorf("%s is set without %s", KeyStorePassphraseEnv, KeyStoreEnv)
		}
		return nil, nil // nolint: nilnil // no key store
	}
	var opts []keystore.FileKeyStoreOption
	if hasPassphrase {
		opts = append(opts, keystore.WithPassphrase([]byte(passphrase)))
	}
	ks, err := keystore.NewFileKeyStore(dir, opts...)
	if err != nil {
		return nil, err
	}
	return ks, nil
}
