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

// Package production bundles the production trust anchors of device
// attestation published on the Distributed Compliance Ledger (DCL) of the
// Connectivity Standards Alliance: the certificates of the keys which sign
// the Certification Declarations of certified products. See
// certs/README.md for their source.
package production

import (
	"embed"
	"io/fs"
	"path"
	"sort"
)

//go:embed certs/cd/*.der
var cdCerts embed.FS

// CDSigningCertificates returns the DER-encoded certificates of the
// Alliance's Certification Declaration signing keys.
func CDSigningCertificates() [][]byte {
	return readAll(cdCerts, "certs/cd")
}

func readAll(fsys embed.FS, dir string) [][]byte {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	certs := make([][]byte, 0, len(names))
	for _, name := range names {
		b, err := fsys.ReadFile(path.Join(dir, name))
		if err != nil {
			continue
		}
		certs = append(certs, b)
	}
	return certs
}
