// Copyright (C) 2022 The go-matter Authors All rights reserved.
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

package mdns

import (
	_ "embed"
	"net"
	"strings"
	"testing"

	"github.com/cybergarage/go-logger/log/hexdump"
	"github.com/cybergarage/go-matter/matter/mdns"
	"github.com/cybergarage/go-mdns/mdns/dns"
)

//go:embed dumps/matter-spec-120-4.3.1.13-dns-sd.dump
var matterSpec12043113DNSSD string

//go:embed dumps/matter-spec-120-4.3.1.13-avahi.dump
var matterSpec12043113Avahi string

//go:embed dumps/matter-service-01.dump
var matterService01 string

func TestCommissioningNode(t *testing.T) {
	type expected struct {
		hostname  string
		addrs     []net.IP
		port      int
		venderID  mdns.VendorID
		productID mdns.ProductID
		disc      mdns.Discriminator
		fullDisc  mdns.Discriminator
		shortDisc mdns.Discriminator
		cm        mdns.CommissioningMode
	}
	tests := []struct {
		name     string
		dump     string
		expected expected
	}{
		// 4.3.1.13. Examples
		// dns-sd -R DD200C20D25AE5F7 _matterc._udp,_S3,_L840,_CM . 11111 D=840 CM=2
		{
			"matter 120 4.3.1.13/dns-sd",
			matterSpec12043113DNSSD,
			expected{
				hostname: "DD200C20D25AE5F7",
				addrs: []net.IP{
					net.ParseIP("192.168.100.53"),
					net.ParseIP("fe80::46d:889b:988:3dfc"),
					net.ParseIP("2400:2410:b242:bf00:1845:f0cb:41af:b6fb"),
				},
				port:      11111,
				venderID:  mdns.VendorID(0),
				productID: mdns.ProductID(0),
				disc:      mdns.Discriminator(840),
				fullDisc:  mdns.Discriminator(840),
				shortDisc: mdns.Discriminator(3),
				cm:        mdns.CommissioningModeDynamicPasscode,
			},
		},
		// 4.3.1.13. Examples
		// avahi-publish-service --subtype=_S3._sub._matterc._udp --subtype=_L840._sub._matterc._udp DD200C20D25AE5F7 --subtype=_CM._sub._matterc._udp _matterc._udp 11111 D=840 CM=2
		{
			"matter 120 4.3.1.13/avahi",
			matterSpec12043113Avahi,
			expected{
				hostname: "DD200C20D25AE5F7",
				addrs: []net.IP{
					net.ParseIP("172.17.0.1"),
				},
				port:      11111,
				venderID:  mdns.VendorID(0),
				productID: mdns.ProductID(0),
				disc:      mdns.Discriminator(840),
				fullDisc:  mdns.Discriminator(840),
				shortDisc: mdns.Discriminator(3),
				cm:        mdns.CommissioningModeDynamicPasscode,
			},
		},
		{
			"matter service 01",
			matterService01,
			expected{
				hostname: "89692F67BC97311B",
				addrs: []net.IP{
					net.ParseIP("192.168.100.95"),
				},
				port:      5540,
				venderID:  mdns.VendorID(5002),
				productID: mdns.ProductID(5010),
				disc:      mdns.Discriminator(2377),
				fullDisc:  mdns.Discriminator(2377),
				shortDisc: mdns.Discriminator(9),
				cm:        mdns.CommissioningModePasscode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msgBytes, err := hexdump.DecodeHexdumpLogs(strings.Split(test.dump, "\n"))
			if err != nil {
				t.Error(err)
				return
			}

			msg, err := dns.NewMessageWithBytes(msgBytes)
			if err != nil {
				t.Error(err)
				return
			}

			node, err := mdns.NewCommissioningNodeWithMessage(msg)
			if err != nil {
				t.Log("\n" + msg.String())
				t.Error(err)
				return
			}

			reportError := func(msg dns.Message, node mdns.CommissionableNode, format string, args ...any) {
				t.Errorf(format, args...)
				t.Log("\n" + msg.String())
				t.Log("\n" + node.String())
			}

			if 0 < len(test.expected.hostname) {
				hostname, ok := node.Hostname()
				if !ok {
					reportError(msg, node, "host name not found")
					return
				}
				if hostname != test.expected.hostname {
					reportError(msg, node, "host name (%s) != (%s)", hostname, test.expected.hostname)
					return
				}
			}

			if 0 < len(test.expected.addrs) {
				addrs, ok := node.Addresses()
				if !ok {
					reportError(msg, node, "address not found")
					return
				}
				if len(addrs) != len(test.expected.addrs) {
					reportError(msg, node, "address length (%d) != (%d)", len(addrs), len(test.expected.addrs))
					return
				}
				for _, expectedAddr := range test.expected.addrs {
					found := false
					for _, addr := range addrs {
						if addr.Equal(expectedAddr) {
							found = true
							break
						}
					}
					if !found {
						reportError(msg, node, "expected address (%s) not found in addresses", expectedAddr)
						return
					}
				}
			}

			if 0 < test.expected.port {
				port, ok := node.Port()
				if !ok {
					reportError(msg, node, "port not found")
					return
				}
				if port != test.expected.port {
					reportError(msg, node, "port (%d) != (%d)", port, test.expected.port)
					return
				}
			}

			if 0 < test.expected.venderID {
				vendorID, ok := node.VendorID()
				if !ok {
					reportError(msg, node, "vendor ID not found")
					return
				}
				if vendorID != test.expected.venderID {
					reportError(msg, node, "vendor ID (%s) != (%s)", vendorID, test.expected.venderID)
					return
				}
			}

			if 0 < test.expected.productID {
				productID, ok := node.ProductID()
				if !ok {
					reportError(msg, node, "product ID not found")
					return
				}
				if productID != test.expected.productID {
					reportError(msg, node, "product ID (%s) != (%s)", productID, test.expected.productID)
					return
				}
			}

			if 0 < test.expected.disc {
				disc, ok := node.Discriminator()
				if !ok {
					reportError(msg, node, "discriminator not found")
					return
				}
				if !test.expected.disc.Equal(disc) {
					reportError(msg, node, "discriminator (%s) != (%s)", disc, test.expected.disc)
					return
				}
			}

			if 0 < test.expected.fullDisc {
				disc, ok := node.FullDiscriminator()
				if !ok {
					reportError(msg, node, "full discriminator not found")
					return
				}
				if !test.expected.fullDisc.Equal(disc) {
					reportError(msg, node, "full discriminator (%s) != (%s)", disc, test.expected.fullDisc)
					return
				}
			}

			if 0 < test.expected.shortDisc {
				discs, ok := node.ShortDiscriminator()
				if !ok {
					reportError(msg, node, "short discriminator not found")
					return
				}
				if discs != test.expected.shortDisc {
					reportError(msg, node, "short discriminator (%s) != (%s)", discs, test.expected.shortDisc)
					return
				}
			}

			if 0 < test.expected.cm {
				cm, ok := node.CommissioningMode()
				if !ok {
					reportError(msg, node, "commissioning mode not found")
					return
				}
				if cm != test.expected.cm {
					reportError(msg, node, "commissioning mode (%s) != (%s)", cm, test.expected.cm)
					return
				}
			}
		})
	}
}
