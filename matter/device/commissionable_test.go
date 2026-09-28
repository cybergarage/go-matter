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
	"encoding/binary"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-mdns/mdns/dns"
)

func testService() CommissionableService {
	return CommissionableService{
		InstanceName:      "665F6E75B5D3A9C2",
		Hostname:          "B75AFB458ECD6D6F",
		Port:              5540,
		Discriminator:     3840,
		VendorID:          0xFFF1,
		ProductID:         0x8001,
		CommissioningMode: mdns.CommissioningModePasscode,
		DeviceType:        0x0100,
		DeviceName:        "Test Light",
	}
}

func TestCommissionableServiceNames(t *testing.T) {
	s := testService()
	if got, want := s.InstanceFullName(), "665F6E75B5D3A9C2._matterc._udp.local"; got != want {
		t.Errorf("InstanceFullName() = %q, want %q", got, want)
	}
	if got, want := s.HostFullName(), "B75AFB458ECD6D6F.local"; got != want {
		t.Errorf("HostFullName() = %q, want %q", got, want)
	}
	wantSubtypes := []string{"_L3840", "_S15", "_V65521", "_T256", "_CM"}
	if got := s.Subtypes(); !reflect.DeepEqual(got, wantSubtypes) {
		t.Errorf("Subtypes() = %v, want %v", got, wantSubtypes)
	}
	if got := s.SubtypeFullNames()[0]; got != "_L3840._sub._matterc._udp.local" {
		t.Errorf("SubtypeFullNames()[0] = %q", got)
	}
	wantTXT := []string{"D=3840", "CM=1", "VP=65521+32769", "DT=256", "DN=Test Light"}
	if got := s.TXT(); !reflect.DeepEqual(got, wantTXT) {
		t.Errorf("TXT() = %v, want %v", got, wantTXT)
	}

	// Out of commissioning mode, _CM goes and CM=0 stays.
	s.CommissioningMode = mdns.CommissioningModeAbsence
	for _, st := range s.Subtypes() {
		if st == "_CM" {
			t.Error("Subtypes() includes _CM with CommissioningMode 0")
		}
	}
	if got := s.TXT()[1]; got != "CM=0" {
		t.Errorf("TXT()[1] = %q, want CM=0", got)
	}
}

func TestCommissionableServiceValidate(t *testing.T) {
	if err := testService().Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
	for name, mutate := range map[string]func(*CommissionableService){
		"instance":      func(s *CommissionableService) { s.InstanceName = "665f6e75b5d3a9c2" },
		"host":          func(s *CommissionableService) { s.Hostname = "short" },
		"port":          func(s *CommissionableService) { s.Port = 0 },
		"discriminator": func(s *CommissionableService) { s.Discriminator = 0x1000 },
		"name":          func(s *CommissionableService) { s.DeviceName = strings.Repeat("x", 33) },
		"interval":      func(s *CommissionableService) { s.SessionIdleInterval = MaxSessionInterval + 1 },
	} {
		s := testService()
		mutate(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: Validate() = nil, want an error", name)
		}
	}
	if n := NewInstanceName(); !mdns.HostnameRegexp.MatchString(n) {
		t.Errorf("NewInstanceName() = %q, not 16 uppercase hex digits", n)
	}
}

// TestCommissionableServiceIsDiscoverable encodes the service as the mDNS
// response a responder would send and parses it with the commissioner's own
// discovery code, so the two sides agree on the record format.
func TestCommissionableServiceIsDiscoverable(t *testing.T) {
	s := testService()
	b := encodeDNSResponse(s, net.IPv4(192, 168, 0, 10))
	msg, err := dns.NewMessageWithBytes(b)
	if err != nil {
		t.Fatalf("dns.NewMessageWithBytes(...) error = %v", err)
	}
	node, err := mdns.NewCommissioningNodeWithMessage(msg)
	if err != nil {
		t.Fatalf("NewCommissioningNodeWithMessage(...) error = %v", err)
	}

	if d, ok := node.FullDiscriminator(); !ok || uint16(d) != s.Discriminator {
		t.Errorf("FullDiscriminator() = (%v, %v), want %d", d, ok, s.Discriminator)
	}
	if v, ok := node.VendorID(); !ok || uint16(v) != s.VendorID {
		t.Errorf("VendorID() = (%v, %v), want %d", v, ok, s.VendorID)
	}
	if p, ok := node.ProductID(); !ok || uint16(p) != s.ProductID {
		t.Errorf("ProductID() = (%v, %v), want %d", p, ok, s.ProductID)
	}
	if cm, ok := node.CommissioningMode(); !ok || cm != s.CommissioningMode {
		t.Errorf("CommissioningMode() = (%v, %v), want %v", cm, ok, s.CommissioningMode)
	}
	if n, ok := node.DeviceName(); !ok || n != s.DeviceName {
		t.Errorf("DeviceName() = (%q, %v), want %q", n, ok, s.DeviceName)
	}
	if port, ok := node.Port(); !ok || port != s.Port {
		t.Errorf("Port() = (%v, %v), want %d", port, ok, s.Port)
	}
	// The discovery side's Hostname() takes the first label of the service
	// name, which for a commissionable node is the instance name.
	if h, ok := node.Hostname(); !ok || h != s.InstanceName {
		t.Errorf("Hostname() = (%q, %v), want the instance name %q", h, ok, s.InstanceName)
	}
}

// encodeDNSResponse builds an uncompressed mDNS response carrying the
// DNS-SD records for s: PTR for the service and each subtype, SRV, TXT and
// an A record for the host.
func encodeDNSResponse(s CommissionableService, ip net.IP) []byte {
	const (
		typeA    = 1
		typePTR  = 12
		typeTXT  = 16
		typeSRV  = 33
		classIN  = 1
		flushIN  = 0x8001
		ttl      = 120
		response = 0x8400
	)
	records := make([][]byte, 0, 8)
	rr := func(name string, typ, class uint16, rdata []byte) {
		b := encodeName(name)
		b = binary.BigEndian.AppendUint16(b, typ)
		b = binary.BigEndian.AppendUint16(b, class)
		b = binary.BigEndian.AppendUint32(b, ttl)
		b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
		records = append(records, append(b, rdata...))
	}

	rr(s.ServiceName(), typePTR, classIN, encodeName(s.InstanceFullName()))
	for _, sub := range s.SubtypeFullNames() {
		rr(sub, typePTR, classIN, encodeName(s.InstanceFullName()))
	}
	srv := binary.BigEndian.AppendUint16(nil, 0)
	srv = binary.BigEndian.AppendUint16(srv, 0)
	srv = binary.BigEndian.AppendUint16(srv, uint16(s.Port))
	rr(s.InstanceFullName(), typeSRV, flushIN, append(srv, encodeName(s.HostFullName())...))
	entries := s.TXT()
	txt := make([]byte, 0, len(entries)*16)
	for _, e := range entries {
		txt = append(txt, byte(len(e)))
		txt = append(txt, e...)
	}
	rr(s.InstanceFullName(), typeTXT, flushIN, txt)
	rr(s.HostFullName(), typeA, flushIN, ip.To4())

	msg := binary.BigEndian.AppendUint16(nil, 0)
	msg = binary.BigEndian.AppendUint16(msg, response)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(records)))
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	for _, r := range records {
		msg = append(msg, r...)
	}
	return msg
}

func encodeName(name string) []byte {
	b := make([]byte, 0, len(name)+2)
	for label := range strings.SplitSeq(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}
