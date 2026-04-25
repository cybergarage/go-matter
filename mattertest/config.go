// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cybergarage/go-matter/matter/config"
)

const (
	testAdministratorNodeID   = 0x0000000000000001
	testAdministratorFabricID = 0x0000000000000002
)

// NewAdministratorConfig creates an AdministratorConfig from the test
// certificates in mattertest/certs.
func NewAdministratorConfig() (config.AdministratorConfig, error) {
	certDir, err := testCertDir()
	if err != nil {
		return nil, err
	}

	rootCert, err := readTestCert(certDir, "admin-root-cert.pem")
	if err != nil {
		return nil, err
	}
	noc, err := readTestCert(certDir, "admin-noc.pem")
	if err != nil {
		return nil, err
	}
	privateKey, err := readTestCert(certDir, "admin-private-key.pem")
	if err != nil {
		return nil, err
	}

	return config.NewAdministratorConfig(
		config.WithAdministratorNodeID(testAdministratorNodeID),
		config.WithAdministratorFabricID(testAdministratorFabricID),
		config.WithAdministratorRootCertificate(rootCert),
		config.WithAdministratorNOC(noc),
		config.WithAdministratorPrivateKey(privateKey),
	), nil
}

func testCertDir() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("mattertest: cannot determine test certificate directory")
	}
	return filepath.Join(filepath.Dir(file), "certs"), nil
}

func readTestCert(dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return nil, fmt.Errorf("mattertest: read %s: %w", name, err)
	}
	return b, nil
}
