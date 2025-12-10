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

func TestCommissionee(t *testing.T) {
	type expected struct {
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

			t.Log("\n" + msg.String())

			if 0 < test.expected.disc {
				disc, ok := node.Discriminator()
				if !ok {
					reportError(msg, node, "discriminator not found")
				}
				if !test.expected.disc.Equal(disc) {
					reportError(msg, node, "discriminator (%s) != (%s)", disc, test.expected.disc)
				}
			}

			if 0 < test.expected.fullDisc {
				disc, ok := node.FullDiscriminator()
				if !ok {
					reportError(msg, node, "full discriminator not found")
				}
				if !test.expected.fullDisc.Equal(disc) {
					reportError(msg, node, "full discriminator (%s) != (%s)", disc, test.expected.fullDisc)
				}
			}

			if 0 < test.expected.shortDisc {
				discs, ok := node.ShortDiscriminator()
				if !ok {
					reportError(msg, node, "short discriminator not found")
				}
				if discs != test.expected.shortDisc {
					reportError(msg, node, "short discriminator (%s) != (%s)", discs, test.expected.shortDisc)
				}
			}

			if 0 < test.expected.cm {
				cm, ok := node.CommissioningMode()
				if !ok {
					reportError(msg, node, "commissioning mode not found")
				}
				if cm != test.expected.cm {
					reportError(msg, node, "commissioning mode (%s) != (%s)", cm, test.expected.cm)
				}
			}
		})
	}
}
