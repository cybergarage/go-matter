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
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/scrypt"
)

const (
	keyFileSuffix = ".key"
	// plainKeyType is the PEM type of a key file without a passphrase: a
	// PKCS#8 private key.
	plainKeyType = "PRIVATE KEY"
	// encryptedKeyType is the PEM type of a key file encrypted with a
	// passphrase: a PKCS#8 private key sealed with AES-256-GCM under a
	// scrypt key, whose parameters are in the PEM headers.
	encryptedKeyType = "GO-MATTER ENCRYPTED PRIVATE KEY"
)

// Default scrypt cost of the passphrase key: N=2^15, r=8, p=1.
const (
	DefaultScryptN = 1 << 15
	DefaultScryptR = 8
	DefaultScryptP = 1
)

var (
	// ErrPassphraseRequired is returned for an encrypted key read by a
	// FileKeyStore without a passphrase.
	ErrPassphraseRequired = errors.New("keystore: the key is encrypted; a passphrase is required")
	// ErrWrongPassphrase is returned when a key does not decrypt with the
	// passphrase, or was altered.
	ErrWrongPassphrase = errors.New("keystore: the key does not decrypt: wrong passphrase or altered file")
	// ErrNotEncrypted is returned for a key file without encryption read by
	// a FileKeyStore with a passphrase.
	ErrNotEncrypted = errors.New("keystore: the key is not encrypted, but the store has a passphrase")
	// ErrKeyFilePermissions is returned for an unencrypted key file which
	// others than its owner can read.
	ErrKeyFilePermissions = errors.New("keystore: the key file can be read by others than its owner")
)

// FileKeyStore keeps each key in a file of its own, <name>.key in its
// directory, readable by its owner only. With a passphrase it encrypts the
// keys with AES-256-GCM under a key derived from the passphrase with
// scrypt; without, it writes them as PKCS#8 PEM, as OpenSSL does.
type FileKeyStore struct {
	dir        string
	passphrase []byte
	scryptN    int
	scryptR    int
	scryptP    int
	mutex      sync.Mutex
}

// FileKeyStoreOption configures a FileKeyStore.
type FileKeyStoreOption func(*FileKeyStore)

// WithPassphrase encrypts the keys with passphrase, and reads only
// encrypted keys.
func WithPassphrase(passphrase []byte) FileKeyStoreOption {
	return func(s *FileKeyStore) {
		s.passphrase = bytes.Clone(passphrase)
	}
}

// NewFileKeyStore returns a FileKeyStore in dir, which it creates readable
// by its owner only when it does not exist.
func NewFileKeyStore(dir string, opts ...FileKeyStoreOption) (*FileKeyStore, error) {
	s := &FileKeyStore{
		dir:        dir,
		passphrase: nil,
		scryptN:    DefaultScryptN,
		scryptR:    DefaultScryptR,
		scryptP:    DefaultScryptP,
		mutex:      sync.Mutex{},
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.passphrase != nil && len(s.passphrase) == 0 {
		return nil, errors.New("keystore: empty passphrase")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keystore: create %s: %w", dir, err)
	}
	return s, nil
}

// Dir returns the directory of the key files.
func (s *FileKeyStore) Dir() string {
	return s.dir
}

// Encrypted reports whether the store encrypts its keys.
func (s *FileKeyStore) Encrypted() bool {
	return s.passphrase != nil
}

func (s *FileKeyStore) path(name string) string {
	return filepath.Join(s.dir, name+keyFileSuffix)
}

// Signer reads the key named name.
func (s *FileKeyStore) Signer(name string) (crypto.Signer, error) {
	if err := ValidateKeyName(name); err != nil {
		return nil, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	path := s.path(name)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("keystore: read %s: %w", name, err)
	}
	block, rest := pem.Decode(b)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("keystore: %s is not a PEM key file", name)
	}
	var der []byte
	switch block.Type {
	case encryptedKeyType:
		if s.passphrase == nil {
			return nil, fmt.Errorf("%w: %s", ErrPassphraseRequired, name)
		}
		if der, err = s.open(name, block); err != nil {
			return nil, err
		}
	case plainKeyType:
		if s.passphrase != nil {
			return nil, fmt.Errorf("%w: %s", ErrNotEncrypted, name)
		}
		if err := checkPrivate(path); err != nil {
			return nil, err
		}
		der = block.Bytes
	default:
		return nil, fmt.Errorf("keystore: %s has PEM type %q", name, block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("keystore: parse %s: %w", name, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || checkKey(key) != nil {
		return nil, fmt.Errorf("keystore: %s is not a P-256 key", name)
	}
	return key, nil
}

// Generate creates a P-256 key named name and writes it.
func (s *FileKeyStore) Generate(name string) (crypto.Signer, error) {
	key, err := generateKey()
	if err != nil {
		return nil, err
	}
	if err := s.Import(name, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Import writes key under name.
func (s *FileKeyStore) Import(name string, key *ecdsa.PrivateKey) error {
	if err := ValidateKeyName(name); err != nil {
		return err
	}
	if err := checkKey(key); err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("keystore: encode %s: %w", name, err)
	}
	block := &pem.Block{Type: plainKeyType, Headers: nil, Bytes: der}
	if s.passphrase != nil {
		if block, err = s.seal(name, der); err != nil {
			return err
		}
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return writeNew(s.dir, s.path(name), name, pem.EncodeToMemory(block))
}

// Delete removes the file of the key named name.
func (s *FileKeyStore) Delete(name string) error {
	if err := ValidateKeyName(name); err != nil {
		return err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	err := os.Remove(s.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrKeyNotFound, name)
	}
	if err != nil {
		return fmt.Errorf("keystore: delete %s: %w", name, err)
	}
	return nil
}

// writeNew writes b to path through a temporary file, so that a key file is
// whole or absent, and fails when path exists.
func writeNew(dir, path, name string, b []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return fmt.Errorf("keystore: write %s: %w", name, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		_ = tmp.Close()
		return fmt.Errorf("keystore: write %s: %w", name, err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("keystore: write %s: %w", name, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("keystore: write %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keystore: write %s: %w", name, err)
	}
	// A link, unlike a rename, does not replace an existing key.
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrKeyExists, name)
		}
		return fmt.Errorf("keystore: write %s: %w", name, err)
	}
	return nil
}

// checkPrivate refuses an unencrypted key file others can read, as OpenSSH
// does.
func checkPrivate(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s (mode %v)", ErrKeyFilePermissions, path, info.Mode().Perm())
	}
	return nil
}

// aad binds a sealed key to its name, so that a key file renamed to
// another key's name does not decrypt.
func aad(name string) []byte {
	return []byte("go-matter keystore v1 " + name)
}

func (s *FileKeyStore) aead(salt []byte, n, r, p int) (cipher.AEAD, error) {
	key, err := scrypt.Key(s.passphrase, salt, n, r, p, 32)
	if err != nil {
		return nil, fmt.Errorf("keystore: derive the passphrase key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *FileKeyStore) seal(name string, der []byte) (*pem.Block, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("keystore: salt: %w", err)
	}
	aead, err := s.aead(salt, s.scryptN, s.scryptR, s.scryptP)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keystore: nonce: %w", err)
	}
	return &pem.Block{
		Type: encryptedKeyType,
		Headers: map[string]string{
			"KDF":        "scrypt",
			"KDF-Params": fmt.Sprintf("N=%d,r=%d,p=%d", s.scryptN, s.scryptR, s.scryptP),
			"Salt":       hex.EncodeToString(salt),
			"Cipher":     "AES-256-GCM",
			"Nonce":      hex.EncodeToString(nonce),
		},
		Bytes: aead.Seal(nil, nonce, der, aad(name)),
	}, nil
}

func (s *FileKeyStore) open(name string, block *pem.Block) ([]byte, error) {
	h := block.Headers
	if h["KDF"] != "scrypt" || h["Cipher"] != "AES-256-GCM" {
		return nil, fmt.Errorf("keystore: %s: unsupported encryption %q/%q", name, h["KDF"], h["Cipher"])
	}
	n, r, p, err := parseScryptParams(h["KDF-Params"])
	if err != nil {
		return nil, fmt.Errorf("keystore: %s: %w", name, err)
	}
	salt, err := hex.DecodeString(h["Salt"])
	if err != nil || len(salt) < 16 {
		return nil, fmt.Errorf("keystore: %s: invalid salt", name)
	}
	nonce, err := hex.DecodeString(h["Nonce"])
	if err != nil {
		return nil, fmt.Errorf("keystore: %s: invalid nonce", name)
	}
	aead, err := s.aead(salt, n, r, p)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("keystore: %s: invalid nonce", name)
	}
	der, err := aead.Open(nil, nonce, block.Bytes, aad(name))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrWrongPassphrase, name)
	}
	return der, nil
}

// parseScryptParams parses "N=..,r=..,p=..", within bounds which keep a
// crafted file from taking the memory or the time of the process.
func parseScryptParams(s string) (int, int, int, error) {
	values := map[string]int{}
	for _, field := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(field, "=")
		if !ok {
			return 0, 0, 0, errors.New("invalid scrypt parameters")
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, 0, 0, errors.New("invalid scrypt parameters")
		}
		values[k] = n
	}
	n, r, p := values["N"], values["r"], values["p"]
	// scrypt takes 128*N*r bytes: at most 256 MiB.
	if n < 1<<10 || n > 1<<20 || n&(n-1) != 0 || r < 1 || r > 32 || p < 1 || p > 16 || n*r > 1<<21 {
		return 0, 0, 0, fmt.Errorf("scrypt parameters N=%d, r=%d, p=%d out of bounds", n, r, p)
	}
	return n, r, p, nil
}

var (
	_ KeyStore = (*FileKeyStore)(nil)
	_ Importer = (*FileKeyStore)(nil)
)
