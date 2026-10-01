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

package device

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"sync"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/credentials"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	caseprotocol "github.com/cybergarage/go-matter/matter/protocol/case"
	"github.com/cybergarage/go-matter/matter/protocol/im"
	"github.com/cybergarage/go-matter/matter/store"
)

// Operational Credentials cluster (Matter Core 11.18).
const (
	OperationalCredentialsClusterID im.ClusterID = 0x003E

	attestationRequestCommandID        im.CommandID = 0x00
	attestationResponseCommandID       im.CommandID = 0x01
	certificateChainRequestCommandID   im.CommandID = 0x02
	certificateChainResponseCommandID  im.CommandID = 0x03
	csrRequestCommandID                im.CommandID = 0x04
	csrResponseCommandID               im.CommandID = 0x05
	addNOCCommandID                    im.CommandID = 0x06
	updateNOCCommandID                 im.CommandID = 0x07
	nocResponseCommandID               im.CommandID = 0x08
	updateFabricLabelCommandID         im.CommandID = 0x09
	removeFabricCommandID              im.CommandID = 0x0A
	addTrustedRootCertificateCommandID im.CommandID = 0x0B

	nocsAttributeID                    im.AttributeID = 0x0000
	fabricsAttributeID                 im.AttributeID = 0x0001
	supportedFabricsAttributeID        im.AttributeID = 0x0002
	commissionedFabricsAttributeID     im.AttributeID = 0x0003
	trustedRootCertificatesAttributeID im.AttributeID = 0x0004
	currentFabricIndexAttributeID      im.AttributeID = 0x0005

	operationalCredentialsClusterRevision = 1

	// fabricIndexTag is the context tag of the FabricIndex field of a
	// fabric-scoped struct (Matter Core 7.13.6).
	fabricIndexTag = 0xFE

	// attestationNonceLength is the length of the AttestationNonce and
	// CSRNonce fields (11.18.4.6).
	attestationNonceLength = 32
	// ipkLength is the length of an epoch key such as the IPK (4.16.2).
	ipkLength = 16
	// maxFabricLabelLength is the longest fabric label (11.18.4.5).
	maxFabricLabelLength = 32
)

// DefaultSupportedFabrics is how many fabrics a Device can join unless
// WithSupportedFabrics says otherwise; Matter requires at least 5
// (11.18.6.3).
const DefaultSupportedFabrics = 5

// CertificateChainType is the CertificateChainTypeEnum (11.18.4.2).
type CertificateChainType uint8

const (
	CertificateChainDAC CertificateChainType = 1
	CertificateChainPAI CertificateChainType = 2
)

// NOCStatus is the NodeOperationalCertStatusEnum a NOCResponse carries
// (11.18.4.3).
type NOCStatus uint8

const (
	NOCStatusOK                  NOCStatus = 0
	NOCStatusInvalidPublicKey    NOCStatus = 1
	NOCStatusInvalidNodeOpID     NOCStatus = 2
	NOCStatusInvalidNOC          NOCStatus = 3
	NOCStatusMissingCsr          NOCStatus = 4
	NOCStatusTableFull           NOCStatus = 5
	NOCStatusInvalidAdminSubject NOCStatus = 6
	NOCStatusFabricConflict      NOCStatus = 9
	NOCStatusLabelConflict       NOCStatus = 10
	NOCStatusInvalidFabricIndex  NOCStatus = 11
)

// operationalCredentials is the server of the Operational Credentials
// cluster. What commissioning stages (the operational key from CSRRequest,
// the root from AddTrustedRootCertificate, the fabric from AddNOC) belongs
// to one arming of the fail-safe: the fabric is written through the
// fail-safe's transaction, and the rest is discarded when the fail-safe is
// armed anew.
type operationalCredentials struct {
	mutex       sync.Mutex
	store       store.DeviceStore
	failSafe    *failSafe
	attestation credentials.AttestationProvider
	maxFabrics  uint8
	now         func() time.Time
	// lookup tells the fabric a session accesses the device on.
	lookup sessionLookup
	// onFabricRemoved is called, once RemoveFabric's response is sent,
	// with the fabric it removed.
	onFabricRemoved func(fabricIndex uint8)
	// onFabricAdded is called when AddNOC adds a fabric over sess, which
	// is from then on bound to that fabric (11.18.6.8).
	onFabricAdded func(sess im.SecureSession, fabricIndex uint8)
	// onFabricUpdated is called when UpdateNOC updates a fabric's NOC.
	onFabricUpdated func(fabricIndex uint8)

	epoch      uint64
	pendingKey *ecdsa.PrivateKey
	// pendingForUpdate tells whether pendingKey is for UpdateNOC, as its
	// CSRRequest asked, rather than for AddNOC.
	pendingForUpdate bool
	pendingRoot      *credentials.OperationalCertificate
	addedFabric      uint8
	// updatedFabric is the fabric UpdateNOC updated under the fail-safe;
	// one arming allows a single AddNOC or UpdateNOC.
	updatedFabric uint8
}

func newOperationalCredentials(s store.DeviceStore, fs *failSafe, attestation credentials.AttestationProvider, maxFabrics uint8) *operationalCredentials {
	return &operationalCredentials{
		mutex:       sync.Mutex{},
		store:       s,
		failSafe:    fs,
		attestation: attestation,
		maxFabrics:  maxFabrics,
		now:         time.Now,
		epoch:       0,

		lookup:          nil,
		onFabricRemoved: nil,
		onFabricAdded:   nil,
		onFabricUpdated: nil,
		pendingKey:      nil,

		pendingForUpdate: false,
		pendingRoot:      nil,
		addedFabric:      0,
		updatedFabric:    0,
	}
}

// register adds the cluster to srv on the root endpoint.
func (oc *operationalCredentials) register(srv *im.Server) {
	// The commands, and reading the NOCs, need Administer (11.18.5, 11.18.6).
	administer := im.WithPrivilege(im.PrivilegeAdminister)
	srv.HandleCommand(rootEndpoint, OperationalCredentialsClusterID, attestationRequestCommandID, oc.attestationRequest, administer, im.WithResponseCommand(attestationResponseCommandID))
	srv.HandleCommand(rootEndpoint, OperationalCredentialsClusterID, certificateChainRequestCommandID, oc.certificateChainRequest, administer, im.WithResponseCommand(certificateChainResponseCommandID))
	srv.HandleCommand(rootEndpoint, OperationalCredentialsClusterID, csrRequestCommandID, oc.csrRequest, administer, im.WithResponseCommand(csrResponseCommandID))
	srv.HandleCommand(rootEndpoint, OperationalCredentialsClusterID, addTrustedRootCertificateCommandID, oc.addTrustedRootCertificate, administer)
	srv.HandleCommand(rootEndpoint, OperationalCredentialsClusterID, addNOCCommandID, oc.addNOC, administer, im.WithResponseCommand(nocResponseCommandID))
	srv.HandleCommand(rootEndpoint, OperationalCredentialsClusterID, updateNOCCommandID, oc.updateNOC, administer, im.WithResponseCommand(nocResponseCommandID))
	srv.HandleCommand(rootEndpoint, OperationalCredentialsClusterID, updateFabricLabelCommandID, oc.updateFabricLabel, administer, im.WithResponseCommand(nocResponseCommandID))
	srv.HandleCommand(rootEndpoint, OperationalCredentialsClusterID, removeFabricCommandID, oc.removeFabric, administer, im.WithResponseCommand(nocResponseCommandID))

	srv.HandleAttributeRead(rootEndpoint, OperationalCredentialsClusterID, nocsAttributeID, oc.readNOCs, administer)
	srv.HandleAttributeRead(rootEndpoint, OperationalCredentialsClusterID, fabricsAttributeID, oc.readFabrics)
	srv.HandleAttribute(rootEndpoint, OperationalCredentialsClusterID, supportedFabricsAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned1(tag, oc.maxFabrics)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, OperationalCredentialsClusterID, commissionedFabricsAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		fabrics, err := oc.fabrics()
		if err != nil {
			return im.StatusFailure
		}
		enc.PutUnsigned1(tag, uint8(len(fabrics)))
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, OperationalCredentialsClusterID, trustedRootCertificatesAttributeID, oc.readTrustedRootCertificates)
	srv.HandleAttributeRead(rootEndpoint, OperationalCredentialsClusterID, currentFabricIndexAttributeID, func(req *im.AttributeRequest, enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned1(tag, oc.accessingFabric(req.Session))
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, OperationalCredentialsClusterID, featureMapAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned4(tag, 0)
		return im.StatusSuccess
	})
	srv.HandleAttribute(rootEndpoint, OperationalCredentialsClusterID, clusterRevisionAttributeID, func(enc tlv.Encoder, tag tlv.Tag) im.Status {
		enc.PutUnsigned2(tag, operationalCredentialsClusterRevision)
		return im.StatusSuccess
	})
}

// armedLocked returns the fail-safe's transaction, discarding what was
// staged under an earlier arming, or nil when the fail-safe is not armed.
func (oc *operationalCredentials) armedLocked() store.DeviceStoreTx {
	tx, epoch := oc.failSafe.armedTransaction()
	if tx == nil || epoch != oc.epoch {
		oc.epoch = epoch
		oc.pendingKey = nil
		oc.pendingForUpdate = false
		oc.pendingRoot = nil
		oc.addedFabric = 0
		oc.updatedFabric = 0
	}
	return tx
}

// view returns what the attributes report: the fail-safe's transaction,
// which sees the fabric AddNOC staged, while it is armed, and the store
// otherwise.
func (oc *operationalCredentials) view() store.DeviceStoreReader {
	if tx, _ := oc.failSafe.armedTransaction(); tx != nil {
		return tx
	}
	return oc.store
}

// fabrics lists the fabrics r holds, by fabric index.
func listFabrics(r store.DeviceStoreReader) ([]store.DeviceFabricRecord, error) {
	var fabrics []store.DeviceFabricRecord
	for index := store.MinFabricIndex; index <= store.MaxFabricIndex; index++ {
		rec, ok, err := r.LoadDeviceFabric(index)
		if err != nil {
			return nil, err
		}
		if ok {
			fabrics = append(fabrics, rec)
		}
	}
	return fabrics, nil
}

func (oc *operationalCredentials) fabrics() ([]store.DeviceFabricRecord, error) {
	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	return listFabrics(oc.view())
}

func sessionChallenge(req *im.CommandRequest) []byte {
	if req.Session == nil || req.Session.SessionKeys() == nil {
		return nil
	}
	return req.Session.SessionKeys().AttestationChallenge()
}

// nonceField reads a 32-byte nonce field.
func nonceField(req *im.CommandRequest, tag uint8) ([]byte, bool) {
	elem, ok := req.Field(tag)
	if !ok {
		return nil, false
	}
	nonce, ok := elem.Bytes()
	if !ok || len(nonce) != attestationNonceLength {
		return nil, false
	}
	return nonce, true
}

// signedResponse answers with a response command of two fields: elements
// and the DAC's signature over them and the session's attestation
// challenge.
func (oc *operationalCredentials) signedResponse(req *im.CommandRequest, cmd im.CommandID, elements []byte) im.CommandResult {
	challenge := sessionChallenge(req)
	if len(challenge) == 0 {
		return im.CommandStatus(im.StatusFailure)
	}
	sig, err := credentials.SignWithChallenge(oc.attestation.SignWithDAC, elements, challenge)
	if err != nil {
		log.Errorf("device: sign with the DAC: %v", err)
		return im.CommandStatus(im.StatusFailure)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), elements); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	if err := enc.PutOctet(tlv.NewContextTag(1), sig); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(cmd, enc.Bytes())
}

// attestationRequest handles AttestationRequest (11.18.6.1).
func (oc *operationalCredentials) attestationRequest(req *im.CommandRequest) im.CommandResult {
	nonce, ok := nonceField(req, 0)
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	if oc.attestation == nil {
		return im.CommandStatus(im.StatusFailure)
	}
	// The timestamp is 0: the device does not know the time (11.18.4.8).
	elements, err := credentials.BuildAttestationElements(oc.attestation.CertificationDeclaration(), nonce, 0, oc.attestation.FirmwareInformation())
	if err != nil {
		log.Errorf("device: build AttestationElements: %v", err)
		return im.CommandStatus(im.StatusFailure)
	}
	return oc.signedResponse(req, attestationResponseCommandID, elements)
}

// certificateChainRequest handles CertificateChainRequest (11.18.6.3).
func (oc *operationalCredentials) certificateChainRequest(req *im.CommandRequest) im.CommandResult {
	field, ok := req.Field(0)
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	certType, ok := field.Unsigned()
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	if oc.attestation == nil {
		return im.CommandStatus(im.StatusFailure)
	}
	var cert []byte
	switch CertificateChainType(certType) {
	case CertificateChainDAC:
		cert = oc.attestation.DAC()
	case CertificateChainPAI:
		cert = oc.attestation.PAI()
	default:
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), cert); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(certificateChainResponseCommandID, enc.Bytes())
}

// csrRequest handles CSRRequest (11.18.6.5): it generates a new
// operational key, replacing one an earlier CSRRequest generated, and
// answers with a CSR for it.
func (oc *operationalCredentials) csrRequest(req *im.CommandRequest) im.CommandResult {
	nonce, ok := nonceField(req, 0)
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	forUpdate := false
	if field, ok := req.Field(1); ok {
		if forUpdate, ok = field.Bool(); !ok {
			return im.CommandStatus(im.StatusInvalidCommand)
		}
	}
	// A key for UpdateNOC is asked for over CASE, by the fabric whose NOC
	// it replaces (11.18.6.5).
	if forUpdate && (oc.lookup == nil || !oc.lookup(req.Session).isCASE) {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	if oc.attestation == nil {
		return im.CommandStatus(im.StatusFailure)
	}

	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	if oc.armedLocked() == nil {
		return im.CommandStatus(im.StatusFailsafeRequired)
	}
	if oc.addedFabric != 0 || oc.updatedFabric != 0 {
		return im.CommandStatus(im.StatusConstraintError)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	signer, err := credentials.NewSoftwareSigner(key)
	if err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	csr, err := credentials.CreateCSR(signer)
	if err != nil {
		log.Errorf("device: create a CSR: %v", err)
		return im.CommandStatus(im.StatusFailure)
	}
	elements, err := credentials.BuildNOCSRElements(csr, nonce)
	if err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	result := oc.signedResponse(req, csrResponseCommandID, elements)
	if result.HasResponse {
		oc.pendingKey = key
		oc.pendingForUpdate = forUpdate
	}
	return result
}

// addTrustedRootCertificate handles AddTrustedRootCertificate
// (11.18.6.13): it stages the root the NOC of the following AddNOC must
// chain to.
func (oc *operationalCredentials) addTrustedRootCertificate(req *im.CommandRequest) im.CommandResult {
	field, ok := req.Field(0)
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	rootTLV, ok := field.Bytes()
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}

	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	if oc.armedLocked() == nil {
		return im.CommandStatus(im.StatusFailsafeRequired)
	}
	if oc.pendingRoot != nil || oc.addedFabric != 0 {
		return im.CommandStatus(im.StatusConstraintError)
	}
	root, err := credentials.ParseOperationalCertificate(rootTLV)
	if err == nil {
		err = credentials.VerifyRootCertificate(root)
	}
	if err != nil {
		log.Warnf("device: AddTrustedRootCertificate: %v", err)
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	oc.pendingRoot = root
	return im.CommandStatus(im.StatusSuccess)
}

// nocResponse encodes a NOCResponse (11.18.6.10).
func nocResponse(status NOCStatus, fabricIndex uint8) im.CommandResult {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned1(tlv.NewContextTag(0), uint8(status))
	if fabricIndex != 0 {
		enc.PutUnsigned1(tlv.NewContextTag(1), fabricIndex)
	}
	if err := enc.EndContainer(); err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	return im.CommandResponse(nocResponseCommandID, enc.Bytes())
}

// addNOCRequest is the fields of an AddNOC command (11.18.6.8).
type addNOCRequest struct {
	noc              []byte
	icac             []byte
	ipk              []byte
	caseAdminSubject uint64
	adminVendorID    uint16
}

func decodeAddNOC(req *im.CommandRequest) (addNOCRequest, bool) {
	r := addNOCRequest{noc: nil, icac: nil, ipk: nil, caseAdminSubject: 0, adminVendorID: 0}
	nocField, ok1 := req.Field(0)
	ipkField, ok2 := req.Field(2)
	subjectField, ok3 := req.Field(3)
	vendorField, ok4 := req.Field(4)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return r, false
	}
	var vendor uint64
	r.noc, ok1 = nocField.Bytes()
	r.ipk, ok2 = ipkField.Bytes()
	r.caseAdminSubject, ok3 = subjectField.Unsigned()
	vendor, ok4 = vendorField.Unsigned()
	if !ok1 || !ok2 || !ok3 || !ok4 || 0xFFFF < vendor {
		return r, false
	}
	r.adminVendorID = uint16(vendor)
	if icacField, ok := req.Field(1); ok {
		if r.icac, ok = icacField.Bytes(); !ok {
			return r, false
		}
	}
	return r, true
}

// addNOC handles AddNOC (11.18.6.8): it checks the NOC against the staged
// root and operational key, and writes the new fabric, an Administer ACL
// entry for CaseAdminSubject and the IPK through the fail-safe's
// transaction, so they only last if commissioning completes.
func (oc *operationalCredentials) addNOC(req *im.CommandRequest) im.CommandResult {
	args, ok := decodeAddNOC(req)
	if !ok || len(args.ipk) != ipkLength {
		return im.CommandStatus(im.StatusInvalidCommand)
	}

	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	tx := oc.armedLocked()
	if tx == nil {
		return im.CommandStatus(im.StatusFailsafeRequired)
	}
	if oc.addedFabric != 0 || oc.updatedFabric != 0 || oc.pendingForUpdate {
		return im.CommandStatus(im.StatusConstraintError)
	}
	if oc.pendingKey == nil {
		return nocResponse(NOCStatusMissingCsr, 0)
	}
	if oc.pendingRoot == nil {
		return nocResponse(NOCStatusInvalidNOC, 0)
	}

	noc, err := credentials.ParseOperationalCertificate(args.noc)
	if err != nil {
		log.Warnf("device: AddNOC: %v", err)
		return nocResponse(NOCStatusInvalidNOC, 0)
	}
	var icac *credentials.OperationalCertificate
	if len(args.icac) != 0 {
		if icac, err = credentials.ParseOperationalCertificate(args.icac); err != nil {
			log.Warnf("device: AddNOC: ICAC: %v", err)
			return nocResponse(NOCStatusInvalidNOC, 0)
		}
	}
	if pub, err := oc.pendingKey.PublicKey.ECDH(); err != nil || !bytes.Equal(noc.PublicKey, pub.Bytes()) {
		return nocResponse(NOCStatusInvalidPublicKey, 0)
	}
	if !credentials.IsOperationalNodeID(noc.NodeID) {
		return nocResponse(NOCStatusInvalidNodeOpID, 0)
	}
	if err := credentials.VerifyOperationalChain(noc, icac, oc.pendingRoot); err != nil {
		log.Warnf("device: AddNOC: %v", err)
		return nocResponse(NOCStatusInvalidNOC, 0)
	}
	if !credentials.IsOperationalNodeID(args.caseAdminSubject) && !credentials.IsCASEAuthenticatedTag(args.caseAdminSubject) {
		return nocResponse(NOCStatusInvalidAdminSubject, 0)
	}

	fabrics, err := listFabrics(tx)
	if err != nil {
		log.Errorf("device: AddNOC: list the fabrics: %v", err)
		return im.CommandStatus(im.StatusFailure)
	}
	for _, f := range fabrics {
		if f.FabricID == noc.FabricID && bytes.Equal(f.RootPublicKey, oc.pendingRoot.PublicKey) {
			return nocResponse(NOCStatusFabricConflict, 0)
		}
	}
	index, ok := freeFabricIndex(fabrics)
	if !ok || int(oc.maxFabrics) <= len(fabrics) {
		return nocResponse(NOCStatusTableFull, 0)
	}

	if err := oc.writeFabric(tx, index, noc, icac, args); err != nil {
		log.Errorf("device: AddNOC: write fabric %d: %v", index, err)
		return im.CommandStatus(im.StatusFailure)
	}
	oc.addedFabric = index
	oc.failSafe.addFabric(index)
	if oc.onFabricAdded != nil {
		oc.onFabricAdded(req.Session, index)
	}
	log.Infof("device: AddNOC: joined fabric 0x%016X as node 0x%016X (fabric index %d)", noc.FabricID, noc.NodeID, index)
	return nocResponse(NOCStatusOK, index)
}

// updateNOC handles UpdateNOC (11.18.6.9): over a CASE session of the
// fabric which armed the fail-safe, it replaces that fabric's NOC, ICAC
// and operational key with the ones the NOC was issued for, after a
// CSRRequest for UpdateNOC. The change goes through the fail-safe's
// transaction, so it lasts only if CommissioningComplete follows.
func (oc *operationalCredentials) updateNOC(req *im.CommandRequest) im.CommandResult {
	nocField, ok := req.Field(0)
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	nocTLV, ok := nocField.Bytes()
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	var icacTLV []byte
	if icacField, ok := req.Field(1); ok {
		if icacTLV, ok = icacField.Bytes(); !ok {
			return im.CommandStatus(im.StatusInvalidCommand)
		}
	}
	info := sessionInfo{known: false, isCASE: false, isGroup: false, groupID: 0, fabricIndex: 0, peerNodeID: 0, peerCATs: nil}
	if oc.lookup != nil {
		info = oc.lookup(req.Session)
	}
	if !info.isCASE || info.fabricIndex == 0 {
		return im.CommandStatus(im.StatusUnsupportedAccess)
	}

	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	tx := oc.armedLocked()
	if tx == nil || oc.failSafe.armedFabric() != info.fabricIndex {
		return im.CommandStatus(im.StatusFailsafeRequired)
	}
	if oc.addedFabric != 0 || oc.updatedFabric != 0 {
		return im.CommandStatus(im.StatusConstraintError)
	}
	if oc.pendingKey == nil {
		return nocResponse(NOCStatusMissingCsr, 0)
	}
	if !oc.pendingForUpdate {
		return im.CommandStatus(im.StatusConstraintError)
	}

	rec, ok, err := tx.LoadDeviceFabric(info.fabricIndex)
	if err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	if !ok {
		return nocResponse(NOCStatusInvalidFabricIndex, 0)
	}
	root, err := credentials.ParseOperationalCertificate(rec.RCAC)
	if err != nil {
		log.Errorf("device: UpdateNOC: the root of fabric %d: %v", info.fabricIndex, err)
		return im.CommandStatus(im.StatusFailure)
	}
	noc, err := credentials.ParseOperationalCertificate(nocTLV)
	if err != nil {
		log.Warnf("device: UpdateNOC: %v", err)
		return nocResponse(NOCStatusInvalidNOC, 0)
	}
	var icac *credentials.OperationalCertificate
	if len(icacTLV) != 0 {
		if icac, err = credentials.ParseOperationalCertificate(icacTLV); err != nil {
			log.Warnf("device: UpdateNOC: ICAC: %v", err)
			return nocResponse(NOCStatusInvalidNOC, 0)
		}
	}
	if pub, err := oc.pendingKey.PublicKey.ECDH(); err != nil || !bytes.Equal(noc.PublicKey, pub.Bytes()) {
		return nocResponse(NOCStatusInvalidPublicKey, 0)
	}
	if !credentials.IsOperationalNodeID(noc.NodeID) {
		return nocResponse(NOCStatusInvalidNodeOpID, 0)
	}
	// The new NOC stays on the fabric: under its root, with its fabric ID.
	if err := credentials.VerifyOperationalChain(noc, icac, root); err != nil || noc.FabricID != rec.FabricID {
		log.Warnf("device: UpdateNOC: the NOC is not of fabric %d: %v", info.fabricIndex, err)
		return nocResponse(NOCStatusInvalidNOC, 0)
	}

	key, err := x509.MarshalECPrivateKey(oc.pendingKey)
	if err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	rec.NodeID = noc.NodeID
	rec.NOC = noc.TLV
	rec.ICAC = nil
	if icac != nil {
		rec.ICAC = icac.TLV
	}
	rec.PrivateKey = key
	rec.UpdatedAt = oc.now()
	if err := tx.SaveDeviceFabric(rec); err != nil {
		log.Errorf("device: UpdateNOC: write fabric %d: %v", info.fabricIndex, err)
		return im.CommandStatus(im.StatusFailure)
	}
	oc.updatedFabric = info.fabricIndex
	if oc.onFabricUpdated != nil {
		oc.onFabricUpdated(info.fabricIndex)
	}
	log.Infof("device: UpdateNOC: fabric %d is now node 0x%016X", info.fabricIndex, noc.NodeID)
	return nocResponse(NOCStatusOK, info.fabricIndex)
}

// freeFabricIndex returns the lowest fabric index fabrics, ordered by
// index, leave free.
func freeFabricIndex(fabrics []store.DeviceFabricRecord) (uint8, bool) {
	index := store.MinFabricIndex
	for _, f := range fabrics {
		if f.FabricIndex != index {
			break
		}
		if index == store.MaxFabricIndex {
			return 0, false
		}
		index++
	}
	return index, true
}

func (oc *operationalCredentials) writeFabric(tx store.DeviceStoreTx, index uint8, noc, icac *credentials.OperationalCertificate, args addNOCRequest) error {
	key, err := x509.MarshalECPrivateKey(oc.pendingKey)
	if err != nil {
		return err
	}
	rec := store.DeviceFabricRecord{
		FabricIndex:   index,
		FabricID:      noc.FabricID,
		NodeID:        noc.NodeID,
		VendorID:      args.adminVendorID,
		RootPublicKey: oc.pendingRoot.PublicKey,
		Label:         "",
		RCAC:          oc.pendingRoot.TLV,
		ICAC:          nil,
		NOC:           noc.TLV,
		PrivateKey:    key,
		UpdatedAt:     oc.now(),
	}
	if icac != nil {
		rec.ICAC = icac.TLV
	}
	if err := tx.SaveDeviceFabric(rec); err != nil {
		return err
	}
	// The administrator gets an Administer entry over CASE (11.18.6.8).
	admin := store.ACLEntry{
		Privilege: store.PrivilegeAdminister,
		AuthMode:  store.AuthModeCASE,
		Subjects:  []uint64{args.caseAdminSubject},
		Targets:   nil,
	}
	if err := tx.SaveACL(index, []store.ACLEntry{admin}); err != nil {
		return err
	}
	// The IPK is the fabric's group key set 0 (4.16.2.2).
	ipk := store.GroupKeysRecord{
		KeySets: []store.GroupKeySet{{
			GroupKeySetID:  0,
			SecurityPolicy: store.GroupKeySecurityPolicyTrustFirst,
			EpochKeys:      []store.EpochKey{{Key: args.ipk, StartTime: 0}},
		}},
		KeyMap: nil,
	}
	return tx.SaveGroupKeys(index, ipk)
}

// accessingFabric returns the fabric sess accesses the device on, or 0.
func (oc *operationalCredentials) accessingFabric(sess im.SecureSession) uint8 {
	if oc.lookup == nil {
		return 0
	}
	return oc.lookup(sess).fabricIndex
}

// scopedFabrics returns the fabrics a read of a fabric-scoped list
// reports: all of them, or those of the accessing fabric when the read is
// fabric-filtered (7.13.6).
func (oc *operationalCredentials) scopedFabrics(req *im.AttributeRequest) ([]store.DeviceFabricRecord, uint8, error) {
	accessing := oc.accessingFabric(req.Session)
	fabrics, err := oc.fabrics()
	if err != nil || !req.FabricFiltered {
		return fabrics, accessing, err
	}
	filtered := make([]store.DeviceFabricRecord, 0, 1)
	for _, f := range fabrics {
		if f.FabricIndex == accessing {
			filtered = append(filtered, f)
		}
	}
	return filtered, accessing, nil
}

// readNOCs reports the NOCs list (11.18.5.1). The certificates are
// fabric-sensitive: an entry of another fabric than the accessing one
// carries only its FabricIndex.
func (oc *operationalCredentials) readNOCs(req *im.AttributeRequest, enc tlv.Encoder, tag tlv.Tag) im.Status {
	fabrics, accessing, err := oc.scopedFabrics(req)
	if err != nil {
		return im.StatusFailure
	}
	enc.BeginArray(tag)
	for _, f := range fabrics {
		enc.BeginStructure(tlv.NewAnonymousTag())
		if f.FabricIndex == accessing {
			if err := enc.PutOctet(tlv.NewContextTag(1), f.NOC); err != nil {
				return im.StatusFailure
			}
			if len(f.ICAC) == 0 {
				enc.PutNull(tlv.NewContextTag(2))
			} else if err := enc.PutOctet(tlv.NewContextTag(2), f.ICAC); err != nil {
				return im.StatusFailure
			}
		}
		enc.PutUnsigned1(tlv.NewContextTag(fabricIndexTag), f.FabricIndex)
		if err := enc.EndContainer(); err != nil {
			return im.StatusFailure
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.StatusFailure
	}
	return im.StatusSuccess
}

// readFabrics reports the Fabrics list of FabricDescriptorStruct
// (11.18.5.2), whose fields are not fabric-sensitive.
func (oc *operationalCredentials) readFabrics(req *im.AttributeRequest, enc tlv.Encoder, tag tlv.Tag) im.Status {
	fabrics, _, err := oc.scopedFabrics(req)
	if err != nil {
		return im.StatusFailure
	}
	enc.BeginArray(tag)
	for _, f := range fabrics {
		enc.BeginStructure(tlv.NewAnonymousTag())
		if err := enc.PutOctet(tlv.NewContextTag(1), f.RootPublicKey); err != nil {
			return im.StatusFailure
		}
		enc.PutUnsigned2(tlv.NewContextTag(2), f.VendorID)
		enc.PutUnsigned8(tlv.NewContextTag(3), f.FabricID)
		enc.PutUnsigned8(tlv.NewContextTag(4), f.NodeID)
		if err := enc.PutUTF8(tlv.NewContextTag(5), f.Label); err != nil {
			return im.StatusFailure
		}
		enc.PutUnsigned1(tlv.NewContextTag(fabricIndexTag), f.FabricIndex)
		if err := enc.EndContainer(); err != nil {
			return im.StatusFailure
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.StatusFailure
	}
	return im.StatusSuccess
}

// aclEntries returns the Access Control entries of a fabric, those staged
// under the armed fail-safe included.
func (oc *operationalCredentials) aclEntries(fabricIndex uint8) ([]store.ACLEntry, error) {
	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	return oc.view().LoadACL(fabricIndex)
}

// readTrustedRootCertificates reports the roots of the fabrics, and the
// root AddTrustedRootCertificate staged for the fabric being added
// (11.18.5.5).
func (oc *operationalCredentials) readTrustedRootCertificates(enc tlv.Encoder, tag tlv.Tag) im.Status {
	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	fabrics, err := listFabrics(oc.view())
	if err != nil {
		return im.StatusFailure
	}
	var roots [][]byte
	for _, f := range fabrics {
		roots = appendUnique(roots, f.RCAC)
	}
	oc.armedLocked()
	if oc.pendingRoot != nil {
		roots = appendUnique(roots, oc.pendingRoot.TLV)
	}
	enc.BeginArray(tag)
	for _, root := range roots {
		if err := enc.PutOctet(tlv.NewAnonymousTag(), root); err != nil {
			return im.StatusFailure
		}
	}
	if err := enc.EndContainer(); err != nil {
		return im.StatusFailure
	}
	return im.StatusSuccess
}

func appendUnique(list [][]byte, b []byte) [][]byte {
	for _, have := range list {
		if bytes.Equal(have, b) {
			return list
		}
	}
	return append(list, b)
}

// responderFabrics returns the fabrics CASE can reach the device on, the
// one AddNOC added under the armed fail-safe included: the commissioner
// completes commissioning over CASE on it.
func (oc *operationalCredentials) responderFabrics() ([]caseprotocol.ResponderFabric, error) {
	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	view := oc.view()
	records, err := listFabrics(view)
	if err != nil {
		return nil, err
	}
	fabrics := make([]caseprotocol.ResponderFabric, 0, len(records))
	for _, rec := range records {
		signer, err := credentials.ParseSoftwareSigner(rec.PrivateKey)
		if err != nil {
			log.Errorf("device: fabric %d: operational key: %v", rec.FabricIndex, err)
			continue
		}
		keys, err := view.LoadGroupKeys(rec.FabricIndex)
		if err != nil {
			return nil, err
		}
		ipk, ok := identityProtectionKey(keys)
		if !ok {
			log.Errorf("device: fabric %d has no IPK", rec.FabricIndex)
			continue
		}
		fabrics = append(fabrics, caseprotocol.ResponderFabric{
			FabricIndex:   rec.FabricIndex,
			FabricID:      rec.FabricID,
			NodeID:        rec.NodeID,
			RootPublicKey: rec.RootPublicKey,
			RCAC:          rec.RCAC,
			ICAC:          rec.ICAC,
			NOC:           rec.NOC,
			IPK:           ipk,
			Signer:        signer,
		})
	}
	return fabrics, nil
}

// identityProtectionKey returns the current epoch key of a fabric's group
// key set 0, its IPK (4.16.2.2).
func identityProtectionKey(keys store.GroupKeysRecord) ([]byte, bool) {
	for _, set := range keys.KeySets {
		if set.GroupKeySetID == 0 && 0 < len(set.EpochKeys) {
			return set.EpochKeys[len(set.EpochKeys)-1].Key, true
		}
	}
	return nil, false
}

// removeFabric handles RemoveFabric (11.18.6.12): it removes the fabric,
// with its ACL and group keys, and once the response is sent the device
// ends the sessions on it and stops advertising it. The fabric AddNOC is
// adding under the armed fail-safe cannot be removed; disarming the
// fail-safe removes it.
func (oc *operationalCredentials) removeFabric(req *im.CommandRequest) im.CommandResult {
	field, ok := req.Field(0)
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	index, ok := field.Unsigned()
	if !ok || index < uint64(store.MinFabricIndex) || uint64(store.MaxFabricIndex) < index {
		return nocResponse(NOCStatusInvalidFabricIndex, 0)
	}
	fabricIndex := uint8(index)

	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	if oc.armedLocked() != nil && oc.addedFabric == fabricIndex {
		return nocResponse(NOCStatusInvalidFabricIndex, 0)
	}
	if _, ok, err := oc.store.LoadDeviceFabric(fabricIndex); err != nil {
		return im.CommandStatus(im.StatusFailure)
	} else if !ok {
		return nocResponse(NOCStatusInvalidFabricIndex, 0)
	}
	if err := oc.store.RemoveDeviceFabric(fabricIndex); err != nil {
		log.Errorf("device: RemoveFabric %d: %v", fabricIndex, err)
		return im.CommandStatus(im.StatusFailure)
	}
	log.Infof("device: RemoveFabric: removed fabric %d", fabricIndex)
	result := nocResponse(NOCStatusOK, fabricIndex)
	if oc.onFabricRemoved != nil {
		removed := oc.onFabricRemoved
		result.AfterResponse = func() { removed(fabricIndex) }
	}
	return result
}

// updateFabricLabel handles UpdateFabricLabel (11.18.6.11): it sets the
// label of the accessing fabric, which no other fabric may use.
func (oc *operationalCredentials) updateFabricLabel(req *im.CommandRequest) im.CommandResult {
	field, ok := req.Field(0)
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	label, ok := field.UTF8()
	if !ok {
		return im.CommandStatus(im.StatusInvalidCommand)
	}
	if maxFabricLabelLength < len(label) {
		return im.CommandStatus(im.StatusConstraintError)
	}
	fabricIndex := oc.accessingFabric(req.Session)
	if fabricIndex == 0 {
		return im.CommandStatus(im.StatusUnsupportedAccess)
	}

	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	// A fabric AddNOC staged is only in the fail-safe's transaction; its
	// label goes there too, and lasts only if commissioning completes.
	var w interface {
		store.DeviceStoreReader
		store.DeviceStoreWriter
	} = oc.store
	if tx := oc.armedLocked(); tx != nil {
		w = tx
	}
	fabrics, err := listFabrics(w)
	if err != nil {
		return im.CommandStatus(im.StatusFailure)
	}
	var rec *store.DeviceFabricRecord
	for i := range fabrics {
		switch {
		case fabrics[i].FabricIndex == fabricIndex:
			rec = &fabrics[i]
		case label != "" && fabrics[i].Label == label:
			return nocResponse(NOCStatusLabelConflict, 0)
		}
	}
	if rec == nil {
		return nocResponse(NOCStatusInvalidFabricIndex, 0)
	}
	rec.Label = label
	rec.UpdatedAt = oc.now()
	if err := w.SaveDeviceFabric(*rec); err != nil {
		log.Errorf("device: UpdateFabricLabel %d: %v", fabricIndex, err)
		return im.CommandStatus(im.StatusFailure)
	}
	return nocResponse(NOCStatusOK, fabricIndex)
}
