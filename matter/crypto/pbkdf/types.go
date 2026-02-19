// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package pbkdf

import (
	"github.com/cybergarage/go-matter/matter/types"
)

// Revision represents the revision of any models.
// 7.1.1. Revision History.
type Revision = types.Revision

// Version represents the version of any attributes.
// 11.1.5.22. SpecificationVersion Attribute.
type Version = types.Version

// TransportMode represents the transport mode.
// 4.3.4. Common TXT Key/Value Pairs.
type TransportMode = types.TransportMode

const (
	// MRP: The MRP provides confirmation of delivery for messages that require reliability.
	MRP = types.MRP
	// TCPClient: The advertising Node implements the TCP Client mode and MAY connect to a peer Node that is a TCP Server.
	TCPClient = types.TCPClient
	// TCPServer: The advertising Node implements the TCP Server mode and SHALL listen for incoming TCP connections.
	TCPServer = types.TCPServer
)
