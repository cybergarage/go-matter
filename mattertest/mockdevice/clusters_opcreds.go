// Copyright (C) 2026 The go-matter Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mockdevice

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cybergarage/go-matter/matter/credentials/chipcert"
	"github.com/cybergarage/go-matter/matter/encoding/tlv"
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// Operational Credentials cluster (0x003E) command IDs, per Matter Core
// Spec 11.18.7 (confirmed against real device wire captures earlier in this
// project's live-commissioning debugging: NOCResponse's own CommandID was
// independently decoded as 0x08 from an actual device's response).
const (
	operationalCredentialsClusterID    im.ClusterID = 0x003E
	attestationRequestCommandID        im.CommandID = 0x00
	attestationResponseCommandID       im.CommandID = 0x01
	certificateChainRequestCommandID   im.CommandID = 0x02
	certificateChainResponseCommandID  im.CommandID = 0x03
	csrRequestCommandID                im.CommandID = 0x04
	csrResponseCommandID               im.CommandID = 0x05
	addNOCCommandID                    im.CommandID = 0x06
	addTrustedRootCertificateCommandID im.CommandID = 0x0B
	nocResponseCommandID               im.CommandID = 0x08
)

var (
	oidMatterNodeID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}
	oidMatterFabricID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}
)

// registerOperationalCredentialsHandlers wires AttestationRequest,
// CertificateChainRequest, CSRRequest, AddTrustedRootCertificate, and AddNOC
// into srv, reading/writing fs as each step's state accumulates.
// attestationChallenge returns the PASE session's AttestationChallenge,
// which every DAC-signed response is computed over alongside its own TLV
// bytes (spec 11.18.7.2 / 11.18.7.6). onAddNOC, if non-nil, is invoked once
// AddNOC succeeds — AddNOC is always the last PASE-phase Operational
// Credentials step before a commissioner moves on to Network Commissioning
// (skipped when the device is already on its operational network) and then
// CASE, so this is device.go's signal to stop serving IM-over-PASE requests
// and switch to handleCASE.
func registerOperationalCredentialsHandlers(srv *imServer, fs *fabricState, attestationChallenge func() []byte, onAddNOC func()) {
	srv.handleInvoke(defaultEndpointID, operationalCredentialsClusterID, attestationRequestCommandID, func(fields map[uint8]tlv.Element) (im.CommandID, []byte, error) {
		nonce, ok := fields[0].Bytes()
		if !ok {
			return 0, nil, fmt.Errorf("mockdevice: AttestationRequest missing nonce")
		}
		elements, err := encodeAttestationElements([]byte("mockdevice-certification-declaration"), nonce, uint32(time.Now().Unix()))
		if err != nil {
			return 0, nil, err
		}
		sig, err := signRaw(fs.attestation.dacPriv, append(append([]byte(nil), elements...), attestationChallenge()...))
		if err != nil {
			return 0, nil, err
		}
		respFields, err := encodeTwoOctetFields(elements, sig)
		return attestationResponseCommandID, respFields, err
	})

	srv.handleInvoke(defaultEndpointID, operationalCredentialsClusterID, certificateChainRequestCommandID, func(fields map[uint8]tlv.Element) (im.CommandID, []byte, error) {
		certType, ok := fields[0].Unsigned1()
		if !ok {
			return 0, nil, fmt.Errorf("mockdevice: CertificateChainRequest missing certificateType")
		}
		var certDER []byte
		switch certType {
		case 1: // DAC
			certDER = fs.attestation.dacCertDER
		case 2: // PAI
			certDER = fs.attestation.paiCertDER
		default:
			return 0, nil, fmt.Errorf("mockdevice: CertificateChainRequest unknown certificateType %d", certType)
		}
		respFields, err := encodeOneOctetField(certDER)
		return certificateChainResponseCommandID, respFields, err
	})

	srv.handleInvoke(defaultEndpointID, operationalCredentialsClusterID, csrRequestCommandID, func(fields map[uint8]tlv.Element) (im.CommandID, []byte, error) {
		nonce, ok := fields[0].Bytes()
		if !ok {
			return 0, nil, fmt.Errorf("mockdevice: CSRRequest missing csrNonce")
		}
		nocKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return 0, nil, fmt.Errorf("mockdevice: generate NOC key: %w", err)
		}
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, nocKey)
		if err != nil {
			return 0, nil, fmt.Errorf("mockdevice: create CSR: %w", err)
		}
		fs.nocKey = nocKey
		elements, err := encodeNOCSRElements(csrDER, nonce)
		if err != nil {
			return 0, nil, err
		}
		sig, err := signRaw(fs.attestation.dacPriv, append(append([]byte(nil), elements...), attestationChallenge()...))
		if err != nil {
			return 0, nil, err
		}
		respFields, err := encodeTwoOctetFields(elements, sig)
		return csrResponseCommandID, respFields, err
	})

	srv.handleInvoke(defaultEndpointID, operationalCredentialsClusterID, addTrustedRootCertificateCommandID, func(fields map[uint8]tlv.Element) (im.CommandID, []byte, error) {
		rootTLV, ok := fields[0].Bytes()
		if !ok {
			return 0, nil, fmt.Errorf("mockdevice: AddTrustedRootCertificate missing rootCertTLV")
		}
		rootDER, err := chipcert.TLVToDER(rootTLV)
		if err != nil {
			return 0, nil, fmt.Errorf("mockdevice: decode root certificate: %w", err)
		}
		fs.rootCertDER = rootDER
		// AddTrustedRootCertificate has no defined response payload
		// (spec 11.18.7.11): a bare CommandStatusIB{SUCCESS}, signaled here
		// by returning nil fields.
		return 0, nil, nil
	})

	srv.handleInvoke(defaultEndpointID, operationalCredentialsClusterID, addNOCCommandID, func(fields map[uint8]tlv.Element) (im.CommandID, []byte, error) {
		nocTLV, ok := fields[0].Bytes()
		if !ok {
			return 0, nil, fmt.Errorf("mockdevice: AddNOC missing nocValue")
		}
		nocDER, err := chipcert.TLVToDER(nocTLV)
		if err != nil {
			return 0, nil, fmt.Errorf("mockdevice: decode NOC: %w", err)
		}
		var icacDER []byte
		if icacElem, ok := fields[1]; ok {
			icacTLV, ok := icacElem.Bytes()
			if !ok {
				return 0, nil, fmt.Errorf("mockdevice: AddNOC icacValue is not an octet string")
			}
			icacDER, err = chipcert.TLVToDER(icacTLV)
			if err != nil {
				return 0, nil, fmt.Errorf("mockdevice: decode ICAC: %w", err)
			}
		}
		ipk, ok := fields[2].Bytes()
		if !ok {
			return 0, nil, fmt.Errorf("mockdevice: AddNOC missing ipkValue")
		}
		caseAdminSubject, ok := fields[3].Unsigned()
		if !ok {
			return 0, nil, fmt.Errorf("mockdevice: AddNOC missing caseAdminSubject")
		}
		adminVendorID, ok := fields[4].Unsigned2()
		if !ok {
			return 0, nil, fmt.Errorf("mockdevice: AddNOC missing adminVendorId")
		}

		nodeID, fabricID, err := parseNodeAndFabricID(nocDER)
		if err != nil {
			return 0, nil, fmt.Errorf("mockdevice: AddNOC: %w", err)
		}

		fs.nocDER = nocDER
		fs.icacDER = icacDER
		fs.rawIPK = ipk
		fs.caseAdminSubject = caseAdminSubject
		fs.adminVendorID = adminVendorID
		fs.nodeID = nodeID
		fs.fabricID = fabricID

		respFields, err := encodeNOCResponseFields(0 /* OK */, 1 /* fabricIndex */)
		if err == nil && onAddNOC != nil {
			onAddNOC()
		}
		return nocResponseCommandID, respFields, err
	})
}

// encodeOneOctetField/encodeTwoOctetFields build the CommandFields structure
// (spec 10.7.9's command-fields, a STRUCTURE tagged ContextTag(1)) shared by
// every Operational Credentials response this server sends that carries one
// or two flat octet-string fields at tags 0 and 1.
func encodeOneOctetField(a []byte) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), a); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

func encodeTwoOctetFields(a, b []byte) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	if err := enc.PutOctet(tlv.NewContextTag(0), a); err != nil {
		return nil, err
	}
	if err := enc.PutOctet(tlv.NewContextTag(1), b); err != nil {
		return nil, err
	}
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// encodeNOCResponseFields builds NOCResponse's CommandFields: tag0=StatusCode,
// tag1=FabricIndex. DebugText (tag2) is omitted (optional).
func encodeNOCResponseFields(status, fabricIndex uint8) ([]byte, error) {
	enc := tlv.NewEncoder()
	enc.BeginStructure(tlv.NewContextTag(1))
	enc.PutUnsigned1(tlv.NewContextTag(0), status)
	enc.PutUnsigned1(tlv.NewContextTag(1), fabricIndex)
	if err := enc.EndContainer(); err != nil {
		return nil, err
	}
	return enc.Bytes(), nil
}

// parseNodeAndFabricID extracts the Matter NodeID/FabricID custom-OID
// Subject RDNs from a DER-encoded NOC, matching the hex-string RDN
// convention this repo's own certificate code uses throughout (e.g.
// matter/protocol/case/crypto.go's matterUint64RDN, mattertest/certs/certgen.go's
// uint64ToHexRDNValue) — reimplemented independently here since neither is
// exported.
func parseNodeAndFabricID(nocDER []byte) (uint64, uint64, error) {
	var nodeID, fabricID uint64
	cert, err := x509.ParseCertificate(nocDER)
	if err != nil {
		return 0, 0, fmt.Errorf("parse NOC: %w", err)
	}
	for _, name := range cert.Subject.Names {
		var s string
		switch v := name.Value.(type) {
		case string:
			s = v
		default:
			s = fmt.Sprint(v)
		}
		s = strings.TrimSpace(s)
		switch {
		case name.Type.Equal(oidMatterNodeID):
			nodeID, err = strconv.ParseUint(s, 16, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("parse NodeID RDN %q: %w", s, err)
			}
		case name.Type.Equal(oidMatterFabricID):
			fabricID, err = strconv.ParseUint(s, 16, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("parse FabricID RDN %q: %w", s, err)
			}
		}
	}
	if nodeID == 0 {
		return 0, 0, fmt.Errorf("NOC missing NodeID RDN")
	}
	if fabricID == 0 {
		return 0, 0, fmt.Errorf("NOC missing FabricID RDN")
	}
	return nodeID, fabricID, nil
}
