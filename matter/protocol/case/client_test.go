package caseprotocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cybergarage/go-matter/matter/config"
	"github.com/cybergarage/go-matter/matter/encoding/message"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
)

func TestLoadAdministratorMetadataParsesPEMAndDER(t *testing.T) {
	admin := makeTestAdminMaterials(t)

	pemCfg := config.NewAdministratorConfig(
		config.WithAdministratorNodeID(admin.nodeID),
		config.WithAdministratorFabricID(admin.fabricID),
		config.WithAdministratorRootCertificate(admin.rootPEM),
		config.WithAdministratorNOC(admin.adminNOCDER),
		config.WithAdministratorPrivateKey(admin.adminKeyPKCS8PEM),
	)
	if _, err := LoadAdministratorMetadata(pemCfg); err != nil {
		t.Fatalf("LoadAdministratorMetadata(PEM/DER) error = %v", err)
	}

	derCfg := config.NewAdministratorConfig(
		config.WithAdministratorNodeID(admin.nodeID),
		config.WithAdministratorFabricID(admin.fabricID),
		config.WithAdministratorRootCertificate(admin.rootDER),
		config.WithAdministratorNOC(admin.adminNOCPEM),
		config.WithAdministratorPrivateKey(admin.adminKeySEC1DER),
	)
	if _, err := LoadAdministratorMetadata(derCfg); err != nil {
		t.Fatalf("LoadAdministratorMetadata(DER/PEM) error = %v", err)
	}
}

func TestLoadAdministratorMetadataRejectsMismatchedNodeID(t *testing.T) {
	admin := makeTestAdminMaterials(t)
	cfg := config.NewAdministratorConfig(
		config.WithAdministratorNodeID(admin.nodeID+1),
		config.WithAdministratorFabricID(admin.fabricID),
		config.WithAdministratorRootCertificate(admin.rootDER),
		config.WithAdministratorNOC(admin.adminNOCDER),
		config.WithAdministratorPrivateKey(admin.adminKeyPKCS8DER),
	)
	_, err := LoadAdministratorMetadata(cfg)
	if err == nil || !strings.Contains(err.Error(), "node ID does not match") {
		t.Fatalf("LoadAdministratorMetadata(...) error = %v, want node ID mismatch", err)
	}
}

func TestEncodeDecodeSigmaMessages(t *testing.T) {
	s1, err := encodeSigma1(sigma1{
		InitiatorRandom:    bytesOf(0x11, randomLen),
		InitiatorSessionID: 0x3344,
		DestinationID:      bytesOf(0x22, 32),
		InitiatorEphPubKey: bytesOf(0x33, 65),
	})
	if err != nil {
		t.Fatalf("encodeSigma1(...) error = %v", err)
	}
	dec := tlv.NewDecoderWithBytes(s1)
	if !dec.Next() {
		t.Fatal("Sigma1 decoder did not yield a structure")
	}

	s2Payload, err := encodeTestSigma2Payload()
	if err != nil {
		t.Fatalf("encodeTestSigma2Payload(...) error = %v", err)
	}
	s2, err := decodeSigma2(s2Payload)
	if err != nil {
		t.Fatalf("decodeSigma2(...) error = %v", err)
	}
	if got := len(s2.ResponderRandom); got != randomLen {
		t.Fatalf("len(ResponderRandom) = %d, want %d", got, randomLen)
	}
	if s2.ResponderSessionID != 0x1122 {
		t.Fatalf("ResponderSessionID = 0x%04X, want 0x1122", s2.ResponderSessionID)
	}
	if got := len(s2.ResponderEphPubKey); got != 65 {
		t.Fatalf("len(ResponderEphPubKey) = %d, want 65", got)
	}
	if got := len(s2.Encrypted2); got == 0 {
		t.Fatal("Encrypted2 is empty")
	}
}

func TestEstablishSessionValidatesRequiredInputs(t *testing.T) {
	admin := makeTestAdminMaterials(t)
	initiator := NewInitiator(
		stubTransport{},
		config.NewAdministratorConfig(
			config.WithAdministratorNodeID(admin.nodeID),
			config.WithAdministratorFabricID(admin.fabricID),
			config.WithAdministratorRootCertificate(admin.rootDER),
			config.WithAdministratorNOC(admin.adminNOCDER),
			config.WithAdministratorPrivateKey(admin.adminKeyPKCS8DER),
		),
	)

	_, err := initiator.EstablishSession(context.Background())
	if err == nil || !strings.Contains(err.Error(), "peer node ID is required") {
		t.Fatalf("EstablishSession() error = %v, want missing peer node ID", err)
	}
}

func TestDeriveSessionKeysProducesDistinctDirections(t *testing.T) {
	keys, err := deriveSessionKeys(
		bytesOf(0x01, 32),
		bytesOf(0x02, 16),
		bytesOf(0x03, 10),
		bytesOf(0x04, 10),
		bytesOf(0x05, 10),
		1,
		2,
		3,
		4,
	)
	if err != nil {
		t.Fatalf("deriveSessionKeys(...) error = %v", err)
	}
	if len(keys.I2RKey()) != cryptoSymmetricKeyLen {
		t.Fatalf("len(I2RKey) = %d, want %d", len(keys.I2RKey()), cryptoSymmetricKeyLen)
	}
	if len(keys.R2IKey()) != cryptoSymmetricKeyLen {
		t.Fatalf("len(R2IKey) = %d, want %d", len(keys.R2IKey()), cryptoSymmetricKeyLen)
	}
	if string(keys.I2RKey()) == string(keys.R2IKey()) {
		t.Fatal("I2RKey and R2IKey should differ")
	}
	if keys.LocalNodeID() != 3 {
		t.Errorf("LocalNodeID() = %v, want 3", keys.LocalNodeID())
	}
	if keys.PeerNodeID() != 4 {
		t.Errorf("PeerNodeID() = %v, want 4", keys.PeerNodeID())
	}
}

type stubTransport struct{}

func (stubTransport) Transmit(context.Context, []byte) error  { return nil }
func (stubTransport) Receive(context.Context) ([]byte, error) { return nil, nil }

// retryCountingTransport lets tests observe how many times Transmit/Receive
// were called by transmitAndReceiveWithRetry, and Receive blocks until its
// own ctx expires (simulating a lost packet: nothing ever arrives) for the
// first failReceives calls, then returns a canned response.
type retryCountingTransport struct {
	transmits    int
	receives     int
	failReceives int
	response     []byte
	receiveErr   error
}

func (rt *retryCountingTransport) Transmit(context.Context, []byte) error {
	rt.transmits++
	return nil
}

func (rt *retryCountingTransport) Receive(ctx context.Context) ([]byte, error) {
	rt.receives++
	if rt.receiveErr != nil {
		return nil, rt.receiveErr
	}
	if rt.receives <= rt.failReceives {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return rt.response, nil
}

func withShortCaseRetryTiming(t *testing.T) {
	t.Helper()
	prevAttempts, prevInterval := caseRetryAttempts, caseRetryInterval
	caseRetryAttempts = 3
	caseRetryInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		caseRetryAttempts, caseRetryInterval = prevAttempts, prevInterval
	})
}

func TestTransmitAndReceiveWithRetryRetriesOnTimeout(t *testing.T) {
	withShortCaseRetryTiming(t)
	// receiveSkipAck parses whatever Receive returns as a message.Message,
	// so the canned "response" must itself be a well-formed (non-ack) one.
	respMsg, err := buildCASEMessage(message.CASESigma2, 0, message.NewFirstExchangeID(), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	respBytes, err := respMsg.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	rt := &retryCountingTransport{failReceives: 2, response: respBytes}

	got, err := transmitAndReceiveWithRetry(context.Background(), rt, []byte("sigma1"))
	if err != nil {
		t.Fatalf("transmitAndReceiveWithRetry(...) error = %v", err)
	}
	if string(got) != string(respBytes) {
		t.Errorf("transmitAndReceiveWithRetry(...) = %v, want %v", got, respBytes)
	}
	if rt.transmits != 3 {
		t.Errorf("transmits = %d, want 3 (initial send + 2 retries)", rt.transmits)
	}
}

func TestTransmitAndReceiveWithRetryGivesUpAfterMaxAttempts(t *testing.T) {
	withShortCaseRetryTiming(t)
	rt := &retryCountingTransport{failReceives: caseRetryAttempts}

	_, err := transmitAndReceiveWithRetry(context.Background(), rt, []byte("sigma1"))
	if err == nil {
		t.Fatal("transmitAndReceiveWithRetry(...) error = nil, want timeout after exhausting retries")
	}
	if rt.transmits != caseRetryAttempts {
		t.Errorf("transmits = %d, want %d", rt.transmits, caseRetryAttempts)
	}
}

func TestTransmitAndReceiveWithRetryDoesNotRetryNonTimeoutErrors(t *testing.T) {
	withShortCaseRetryTiming(t)
	rt := &retryCountingTransport{receiveErr: errStatusReport}

	_, err := transmitAndReceiveWithRetry(context.Background(), rt, []byte("sigma1"))
	if !errors.Is(err, errStatusReport) {
		t.Fatalf("transmitAndReceiveWithRetry(...) error = %v, want errStatusReport", err)
	}
	if rt.transmits != 1 {
		t.Errorf("transmits = %d, want 1 (non-timeout errors must not be retried)", rt.transmits)
	}
}

type testAdminMaterials struct {
	nodeID           uint64
	fabricID         uint64
	rootDER          []byte
	rootPEM          []byte
	adminNOCDER      []byte
	adminNOCPEM      []byte
	adminKeyPKCS8DER []byte
	adminKeyPKCS8PEM []byte
	adminKeySEC1DER  []byte
}

func makeTestAdminMaterials(t *testing.T) testAdminMaterials {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root cert: %v", err)
	}

	nodeID := uint64(0x1122334455667788)
	fabricID := uint64(0x2906C908D115D362)
	adminKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("admin key: %v", err)
	}
	adminTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Admin NOC",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier(matterNodeIDOID), Value: "1122334455667788"},
				{Type: asn1.ObjectIdentifier(matterFabricIDOID), Value: "2906C908D115D362"},
			},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	adminNOCDER, err := x509.CreateCertificate(rand.Reader, adminTemplate, rootTemplate, &adminKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("admin cert: %v", err)
	}
	adminKeyPKCS8DER, err := x509.MarshalPKCS8PrivateKey(adminKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	adminKeySEC1DER, err := x509.MarshalECPrivateKey(adminKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	return testAdminMaterials{
		nodeID:           nodeID,
		fabricID:         fabricID,
		rootDER:          rootDER,
		rootPEM:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		adminNOCDER:      adminNOCDER,
		adminNOCPEM:      pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: adminNOCDER}),
		adminKeyPKCS8DER: adminKeyPKCS8DER,
		adminKeyPKCS8PEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: adminKeyPKCS8DER}),
		adminKeySEC1DER:  adminKeySEC1DER,
	}
}

func encodeTestSigma2Payload() ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewAnonymousTag())
	if err := enc.PutOctet(tlv.NewContextTag(1), bytesOf(0x44, randomLen)); err != nil {
		return nil, err
	}
	enc.PutUnsigned2(tlv.NewContextTag(2), 0x1122)
	if err := enc.PutOctet(tlv.NewContextTag(3), bytesOf(0x55, 65)); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(4), bytesOf(0x66, 32)); err != nil {
		return nil, err
	}
	enc.EndContainer()
	return enc.Bytes(), nil
}

func bytesOf(v byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = v
	}
	return out
}

// buildStatusReportWire builds a StatusReport message with the fixed-width,
// little-endian binary payload the wire protocol actually uses (see
// parseStatusReport's doc comment) — NOT TLV, matching connectedhomeip's
// StatusReport::Parse.
func buildStatusReportWire(t *testing.T, generalCode uint16, protocolCode uint16) []byte {
	t.Helper()
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint16(payload[0:2], generalCode)
	binary.LittleEndian.PutUint32(payload[2:6], uint32(message.SecureChannel))
	binary.LittleEndian.PutUint16(payload[6:8], protocolCode)

	msg := message.NewMessage(
		message.WithMessageFrameHeader(message.NewHeader(
			message.WithHeaderSessionID(0),
			message.WithHeaderSecurityFlags(0x00),
			message.WithHeaderMessageCounter(message.NewMessageCounter()),
		)),
		message.WithMessageProtocolHeader(message.NewProtocolHeader(
			message.WithHeaderExchangeFlags(message.ReliabilityFlag),
			message.WithHeaderOpcode(message.StatusReport),
			message.WithHeaderExchangeID(1),
			message.WithHeaderProtocolID(message.SecureChannel),
		)),
		message.WithMessagePayload(payload),
	)
	wire, err := msg.Bytes()
	if err != nil {
		t.Fatalf("msg.Bytes() error = %v", err)
	}
	return wire
}

// TestParseStatusReportFailure guards against a regression where
// parseStatusReport tried to TLV-decode the StatusReport payload; the real
// wire format is a fixed-width, little-endian binary structure (spec
// 4.11.3 / connectedhomeip StatusReport::Parse), not TLV — a real device's
// StatusReport was unparsable ("expected structure, got SignedInt1") until
// this was fixed, even though a self-consistent TLV-encoded test fixture
// happened to pass here before.
func TestParseStatusReportFailure(t *testing.T) {
	wire := buildStatusReportWire(t, 1 /* GeneralCode = FAILURE */, 2)
	if err := parseStatusReport(wire); err == nil {
		t.Fatal("parseStatusReport(...) error = nil, want non-nil")
	}
}

func TestParseStatusReportSuccess(t *testing.T) {
	wire := buildStatusReportWire(t, 0 /* GeneralCode = SUCCESS */, 0)
	if err := parseStatusReport(wire); err != nil {
		t.Fatalf("parseStatusReport(...) error = %v, want nil", err)
	}
}
