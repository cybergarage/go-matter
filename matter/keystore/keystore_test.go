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

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// fastScrypt keeps the tests quick; the format records the parameters.
func fastScrypt(s *FileKeyStore) {
	s.scryptN = 1 << 10
}

func requireSigns(t *testing.T, signer crypto.Signer) {
	t.Helper()
	digest := sha256.Sum256([]byte("message"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("the key does not sign as a P-256 key")
	}
}

func samePublicKey(a, b crypto.Signer) bool {
	pa, _ := a.Public().(*ecdsa.PublicKey)
	return pa != nil && pa.Equal(b.Public())
}

// testKeyStore checks the behavior every KeyStore which generates keys
// shares.
func testKeyStore(t *testing.T, ks KeyStore) {
	t.Helper()
	if _, err := ks.Signer("root"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Signer() of a missing key = %v, want ErrKeyNotFound", err)
	}
	generated, err := ks.Generate("root")
	if err != nil {
		t.Fatal(err)
	}
	requireSigns(t, generated)
	got, err := ks.Signer("root")
	if err != nil {
		t.Fatal(err)
	}
	if !samePublicKey(generated, got) {
		t.Fatal("Signer() returned another key than Generate() made")
	}
	if _, err := ks.Generate("root"); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("Generate() over a key = %v, want ErrKeyExists", err)
	}
	if again, _ := ks.Signer("root"); !samePublicKey(generated, again) {
		t.Fatal("a failed Generate() replaced the key")
	}
	imported, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if importer, ok := ks.(Importer); ok {
		if err := importer.Import("operational", imported); err != nil {
			t.Fatal(err)
		}
		if got, _ := ks.Signer("operational"); got == nil || !samePublicKey(imported, got) {
			t.Fatal("Signer() did not return the imported key")
		}
		if err := importer.Import("operational", imported); !errors.Is(err, ErrKeyExists) {
			t.Fatalf("Import() over a key = %v, want ErrKeyExists", err)
		}
	}
	for _, name := range []string{"", "../root", "Root", "a/b", ".hidden"} {
		if _, err := ks.Generate(name); !errors.Is(err, ErrInvalidKeyName) {
			t.Errorf("Generate(%q) = %v, want ErrInvalidKeyName", name, err)
		}
	}
	if err := ks.Delete("root"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Signer("root"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatal("a deleted key is still there")
	}
	if err := ks.Delete("root"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Delete() of a missing key = %v, want ErrKeyNotFound", err)
	}
}

func TestMemKeyStore(t *testing.T) {
	testKeyStore(t, NewMemKeyStore())
}

func TestFileKeyStore(t *testing.T) {
	ks, err := NewFileKeyStore(filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	testKeyStore(t, ks)
}

func TestEncryptedFileKeyStore(t *testing.T) {
	ks, err := NewFileKeyStore(t.TempDir(), WithPassphrase([]byte("correct horse")), fastScrypt)
	if err != nil {
		t.Fatal(err)
	}
	testKeyStore(t, ks)
}

func TestFileKeyStoreKeepsKeysAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	passphrase := []byte("correct horse")
	ks, err := NewFileKeyStore(dir, WithPassphrase(passphrase), fastScrypt)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ks.Generate("root")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "root.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != encryptedKeyType {
		t.Fatal("the key file is not an encrypted key")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		t.Fatal("the key file holds the key in the clear")
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(filepath.Join(dir, "root.key")); info.Mode().Perm() != 0o600 {
			t.Errorf("key file mode %v, want 0600", info.Mode().Perm())
		}
	}

	reopened, err := NewFileKeyStore(dir, WithPassphrase(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Signer("root")
	if err != nil {
		t.Fatal(err)
	}
	if !samePublicKey(key, got) {
		t.Fatal("the reopened store returned another key")
	}

	wrong, _ := NewFileKeyStore(dir, WithPassphrase([]byte("wrong")))
	if _, err := wrong.Signer("root"); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("Signer() with a wrong passphrase = %v, want ErrWrongPassphrase", err)
	}
	plain, _ := NewFileKeyStore(dir)
	if _, err := plain.Signer("root"); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("Signer() without a passphrase = %v, want ErrPassphraseRequired", err)
	}

	// A key file renamed to another name does not decrypt.
	if err := os.Rename(filepath.Join(dir, "root.key"), filepath.Join(dir, "operational.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Signer("operational"); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("Signer() of a renamed key file = %v, want ErrWrongPassphrase", err)
	}
}

func TestFileKeyStoreRefusesReadableKeys(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permissions")
	}
	dir := t.TempDir()
	ks, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Generate("root"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "root.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Signer("root"); !errors.Is(err, ErrKeyFilePermissions) {
		t.Errorf("Signer() of a world-readable key = %v, want ErrKeyFilePermissions", err)
	}
	encrypted, _ := NewFileKeyStore(dir, WithPassphrase([]byte("p")), fastScrypt)
	if _, err := encrypted.Signer("root"); !errors.Is(err, ErrNotEncrypted) {
		t.Errorf("Signer() of a plain key with a passphrase = %v, want ErrNotEncrypted", err)
	}
}

func TestScryptParamsAreBounded(t *testing.T) {
	for _, s := range []string{"N=1048576,r=32,p=1", "N=1000,r=8,p=1", "N=16384,r=0,p=1", "N=16384", "garbage"} {
		if _, _, _, err := parseScryptParams(s); err == nil {
			t.Errorf("parseScryptParams(%q) succeeded", s)
		}
	}
	if n, r, p, err := parseScryptParams("N=32768,r=8,p=1"); err != nil || n != DefaultScryptN || r != 8 || p != 1 {
		t.Errorf("parseScryptParams(default) = %d, %d, %d, %v", n, r, p, err)
	}
}

func TestStaticKeyStore(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := NewStaticKeyStore(map[string]crypto.Signer{"root": key})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ks.Signer("root"); err != nil || !samePublicKey(key, got) {
		t.Fatalf("Signer() = %v, %v", got, err)
	}
	if _, err := ks.Signer("operational"); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Signer() of a missing key = %v, want ErrKeyNotFound", err)
	}
	if _, err := ks.Generate("operational"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Generate() = %v, want ErrUnsupported", err)
	}
	if _, err := NewStaticKeyStore(map[string]crypto.Signer{"../x": key}); err == nil {
		t.Error("NewStaticKeyStore() took an invalid name")
	}
}
