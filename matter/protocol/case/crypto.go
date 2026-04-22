package caseprotocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	"github.com/cybergarage/go-matter/matter/config"
	mcrypto "github.com/cybergarage/go-matter/matter/crypto"
	"github.com/cybergarage/go-matter/matter/protocol/session"
)

var (
	matterNodeIDOID   = []int{1, 3, 6, 1, 4, 1, 37244, 1, 1}
	matterFabricIDOID = []int{1, 3, 6, 1, 4, 1, 37244, 1, 5}
)

type administratorInputs struct {
	nodeID          uint64
	fabricID        uint64
	rootCertificate *x509.Certificate
	rootPublicKey   []byte
	nocDER          []byte
	icacDER         []byte
	privateKey      *ecdsa.PrivateKey
}

// AdministratorMetadata is the subset of parsed administrator identity used by commissioning.
type AdministratorMetadata struct {
	NodeID        uint64
	FabricID      uint64
	RootPublicKey []byte
}

func loadAdministratorInputs(cfg config.AdministratorConfig) (administratorInputs, error) {
	if cfg == nil {
		return administratorInputs{}, fmt.Errorf("case: administrator config is required")
	}
	nodeID, _ := cfg.NodeID()
	fabricID, _ := cfg.FabricID()
	rootCertBytes, _ := cfg.RootCertificate()
	nocBytes, _ := cfg.NOC()
	icacBytes, _ := cfg.ICAC()
	privateKeyBytes, _ := cfg.PrivateKey()
	if nodeID == 0 {
		return administratorInputs{}, fmt.Errorf("case: administrator config missing node ID")
	}
	if fabricID == 0 {
		return administratorInputs{}, fmt.Errorf("case: administrator config missing fabric ID")
	}
	if len(rootCertBytes) == 0 {
		return administratorInputs{}, fmt.Errorf("case: administrator config missing root certificate")
	}
	if len(nocBytes) == 0 {
		return administratorInputs{}, fmt.Errorf("case: administrator config missing NOC")
	}
	if len(privateKeyBytes) == 0 {
		return administratorInputs{}, fmt.Errorf("case: administrator config missing private key")
	}

	rootCert, err := parseCertificateBytes(rootCertBytes)
	if err != nil {
		return administratorInputs{}, fmt.Errorf("case: parse administrator root certificate: %w", err)
	}
	rootPubKey, err := x509PublicKeyBytes(rootCert)
	if err != nil {
		return administratorInputs{}, fmt.Errorf("case: administrator root public key: %w", err)
	}
	nocDER, err := certificateDERBytes(nocBytes)
	if err != nil {
		return administratorInputs{}, fmt.Errorf("case: parse administrator NOC: %w", err)
	}
	nocCert, err := parseCertificateBytes(nocDER)
	if err != nil {
		return administratorInputs{}, err
	}
	if certNodeID, ok := matterUint64RDN(nocCert, matterNodeIDOID); !ok || certNodeID != nodeID {
		return administratorInputs{}, fmt.Errorf("case: administrator NOC node ID does not match configured administrator node ID")
	}
	if certFabricID, ok := matterUint64RDN(nocCert, matterFabricIDOID); !ok || certFabricID != fabricID {
		return administratorInputs{}, fmt.Errorf("case: administrator NOC fabric ID does not match configured fabric ID")
	}
	var icacDER []byte
	if len(icacBytes) != 0 {
		icacDER, err = certificateDERBytes(icacBytes)
		if err != nil {
			return administratorInputs{}, fmt.Errorf("case: parse administrator ICAC: %w", err)
		}
	}
	privateKey, err := parsePrivateKey(privateKeyBytes)
	if err != nil {
		return administratorInputs{}, fmt.Errorf("case: parse administrator private key: %w", err)
	}
	return administratorInputs{
		nodeID:          nodeID,
		fabricID:        fabricID,
		rootCertificate: rootCert,
		rootPublicKey:   rootPubKey,
		nocDER:          nocDER,
		icacDER:         icacDER,
		privateKey:      privateKey,
	}, nil
}

// LoadAdministratorMetadata parses and validates the administrator config and returns
// the subset needed by operational discovery and CASE routing.
func LoadAdministratorMetadata(cfg config.AdministratorConfig) (AdministratorMetadata, error) {
	inputs, err := loadAdministratorInputs(cfg)
	if err != nil {
		return AdministratorMetadata{}, err
	}
	return AdministratorMetadata{
		NodeID:        inputs.nodeID,
		FabricID:      inputs.fabricID,
		RootPublicKey: cloneBytes(inputs.rootPublicKey),
	}, nil
}

func parseCertificateBytes(b []byte) (*x509.Certificate, error) {
	der, err := certificateDERBytes(b)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func certificateDERBytes(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty certificate")
	}
	if block, _ := pem.Decode(b); block != nil {
		return block.Bytes, nil
	}
	return cloneBytes(b), nil
}

func parsePrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	if block, _ := pem.Decode(b); block != nil {
		b = block.Bytes
	}
	if key, err := x509.ParsePKCS8PrivateKey(b); err == nil {
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unsupported PKCS#8 private key type %T", key)
		}
		return ecdsaKey, nil
	}
	if key, err := x509.ParseECPrivateKey(b); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unsupported private key encoding")
}

func x509PublicKeyBytes(cert *x509.Certificate) ([]byte, error) {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type %T", cert.PublicKey)
	}
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y), nil
}

func matterUint64RDN(cert *x509.Certificate, oidInts []int) (uint64, bool) {
	oid := asn1.ObjectIdentifier(oidInts)
	for _, name := range cert.Subject.Names {
		if !name.Type.Equal(oid) {
			continue
		}
		var s string
		switch v := name.Value.(type) {
		case string:
			s = v
		default:
			s = fmt.Sprint(v)
		}
		s = strings.TrimSpace(s)
		if len(s) == 0 {
			return 0, false
		}
		n, err := strconvParseHexUint64(s)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

func strconvParseHexUint64(s string) (uint64, error) {
	b, err := hex.DecodeString(strings.ToUpper(s))
	if err != nil {
		return 0, err
	}
	if len(b) != 8 {
		return 0, fmt.Errorf("unexpected hex length %d", len(b))
	}
	return binary.BigEndian.Uint64(b), nil
}

func computeDestinationID(ipk, initiatorRandom, rootPublicKey []byte, fabricID, nodeID uint64) []byte {
	fabricBytes := make([]byte, 8)
	nodeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(fabricBytes, fabricID)
	binary.LittleEndian.PutUint64(nodeBytes, nodeID)
	msg := make([]byte, 0, len(initiatorRandom)+len(rootPublicKey)+16)
	msg = append(msg, initiatorRandom...)
	msg = append(msg, rootPublicKey...)
	msg = append(msg, fabricBytes...)
	msg = append(msg, nodeBytes...)
	return mcrypto.CryptoHMAC(ipk, msg)
}

func computeCompressedFabricID(rootPublicKey []byte, fabricID uint64) (uint64, error) {
	if len(rootPublicKey) < 2 {
		return 0, fmt.Errorf("case: invalid root public key")
	}
	fabricBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(fabricBytes, fabricID)
	derived, err := mcrypto.CryptoKDF(rootPublicKey[1:], fabricBytes, []byte("CompressedFabric"), 8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(derived), nil
}

// ComputeCompressedFabricID derives the operational compressed fabric identifier.
func ComputeCompressedFabricID(rootPublicKey []byte, fabricID uint64) (uint64, error) {
	return computeCompressedFabricID(rootPublicKey, fabricID)
}

// ParseCertificateNodeID extracts the Matter operational node ID from an X.509 NOC.
func ParseCertificateNodeID(cert []byte) (uint64, error) {
	parsed, err := parseCertificateBytes(cert)
	if err != nil {
		return 0, err
	}
	nodeID, ok := matterUint64RDN(parsed, matterNodeIDOID)
	if !ok {
		return 0, fmt.Errorf("case: certificate missing matter-node-id subject field")
	}
	return nodeID, nil
}

func ecdhSharedSecret(priv *ecdsa.PrivateKey, peerPubBytes []byte) ([]byte, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), peerPubBytes)
	if x == nil || y == nil {
		return nil, fmt.Errorf("case: invalid peer ephemeral public key")
	}
	sharedX, _ := elliptic.P256().ScalarMult(x, y, priv.D.FillBytes(make([]byte, 32)))
	if sharedX == nil {
		return nil, fmt.Errorf("case: ECDH failed")
	}
	return sharedX.FillBytes(make([]byte, 32)), nil
}

func deriveSigma2Key(sharedSecret, ipk, responderRandom, responderEphPubKey, sigma1Payload []byte) ([]byte, error) {
	transcriptHash := mcrypto.CryptoHash(sigma1Payload)
	salt := append(cloneBytes(ipk), responderRandom...)
	salt = append(salt, responderEphPubKey...)
	salt = append(salt, transcriptHash...)
	return mcrypto.CryptoKDF(sharedSecret, salt, sigma2Info, cryptoSymmetricKeyLen)
}

func deriveSigma3Key(sharedSecret, ipk, sigma1Payload, sigma2Payload []byte) ([]byte, error) {
	transcript := append(cloneBytes(sigma1Payload), sigma2Payload...)
	transcriptHash := mcrypto.CryptoHash(transcript)
	salt := append(cloneBytes(ipk), transcriptHash...)
	return mcrypto.CryptoKDF(sharedSecret, salt, sigma3Info, cryptoSymmetricKeyLen)
}

func deriveSessionKeys(sharedSecret, ipk, sigma1Payload, sigma2Payload, sigma3Payload []byte, initiatorSID, responderSID session.SessionID, localNodeID session.NodeID) (session.SessionKeys, error) {
	transcript := append(cloneBytes(sigma1Payload), sigma2Payload...)
	transcript = append(transcript, sigma3Payload...)
	transcriptHash := mcrypto.CryptoHash(transcript)
	salt := append(cloneBytes(ipk), transcriptHash...)
	derived, err := mcrypto.CryptoKDF(sharedSecret, salt, sessionKeysInfo, 3*cryptoSymmetricKeyLen)
	if err != nil {
		return nil, fmt.Errorf("case: derive session keys: %w", err)
	}
	return newSessionKeys(
		derived[0:cryptoSymmetricKeyLen],
		derived[cryptoSymmetricKeyLen:2*cryptoSymmetricKeyLen],
		initiatorSID,
		responderSID,
		localNodeID,
	), nil
}

func signWithKey(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	sig, err := mcrypto.CryptoSign(privateKeyAdapter{priv}, msg)
	if err != nil {
		return nil, err
	}
	return marshalSignature(sig), nil
}

func verifySignatureFromCert(cert *x509.Certificate, msg, sigBytes []byte) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sig, err := unmarshalSignature(sigBytes)
	if err != nil {
		return false
	}
	return mcrypto.CryptoVerify(publicKeyAdapter{pub}, msg, sig)
}

type privateKeyAdapter struct{ *ecdsa.PrivateKey }
type publicKeyAdapter struct{ *ecdsa.PublicKey }

func (k privateKeyAdapter) Bytes() ([]byte, error) { return x509.MarshalECPrivateKey(k.PrivateKey) }
func (k publicKeyAdapter) Bytes() ([]byte, error) {
	return elliptic.Marshal(k.Curve, k.X, k.Y), nil
}

func marshalSignature(sig mcrypto.Signature) []byte {
	out := make([]byte, signatureLen)
	copy(out[32-len(sig.R()):32], sig.R())
	copy(out[64-len(sig.S()):64], sig.S())
	return out
}

func unmarshalSignature(b []byte) (mcrypto.Signature, error) {
	if len(b) != signatureLen {
		return nil, fmt.Errorf("case: invalid signature length %d", len(b))
	}
	return &caseSignature{
		r: new(big.Int).SetBytes(b[:32]).Bytes(),
		s: new(big.Int).SetBytes(b[32:]).Bytes(),
	}, nil
}

type caseSignature struct {
	r []byte
	s []byte
}

func (s *caseSignature) R() []byte { return cloneBytes(s.r) }
func (s *caseSignature) S() []byte { return cloneBytes(s.s) }
