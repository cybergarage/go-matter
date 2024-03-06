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

package mattertest

import (
	_ "embed"
	"strings"
	"testing"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-mdns/mdns/dns"
)

//go:embed log/matter-spec-120-4.3.1.13.log
var matterSpec12043113 string

func TestCommissionee(t *testing.T) {
	type expected struct {
		disc  string
		discs string
		attrs map[string]string
	}
	tests := []struct {
		name     string
		dumpLog  string
		expected expected
	}{
		// 4.3.1.13. Examples
		// dns-sd -R DD200C20D25AE5F7 _matterc._udp,_S3,_L840,_CM . 11111 D=840 CM=2
		{
			"matter 120 4.3.1.13",
			matterSpec12043113,
			expected{
				disc:  "840",
				discs: "3",
				attrs: map[string]string{
					"D":  "840",
					"CM": "2",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msgBytes, err := log.DecodeHexLog(strings.Split(test.dumpLog, "\n"))
			if err != nil {
				t.Error(err)
				return
			}

			msg, err := dns.NewMessageWithBytes(msgBytes)
			if err != nil {
				t.Error(err)
				return
			}

			com, err := matter.NewCommissioneeWithMessage(msg)
			if err != nil {
				t.Error(err)
				return
			}

			if 0 < len(test.expected.disc) {
				disc, ok := com.LookupDiscriminator()
				if !ok {
					t.Errorf("discriminator not found")
				}
				if disc != test.expected.disc {
					t.Errorf("discriminator (%s) != (%s)", disc, test.expected.disc)
				}
			}

			if 0 < len(test.expected.discs) {
				discs, ok := com.LookupShortDiscriminator()
				if !ok {
					t.Errorf("short discriminator not found")
				}
				if discs != test.expected.discs {
					t.Errorf("short discriminator (%s) != (%s)", discs, test.expected.discs)
				}
			}

			for name, value := range test.expected.attrs {
				attr, ok := com.LookupAttribute(name)
				if !ok {
					t.Errorf("attribute (%s) not found", name)
				}
				if attr != value {
					t.Errorf("attribute (%s) value (%s) != (%s)", name, attr, value)
				}
			}
			t.Log(msg.String())
		})
	}
}
