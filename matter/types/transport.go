// Copyright (C) 2025 The go-matter Authors. All rights reserved.
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

package types

// TransportMode represents the transport mode.
// // 4.3.4. Common TXT Key/Value Pairs.
type TransportMode uint16

const (
	// TCPClient: The advertising Node implements the TCP Client mode and MAY connect to a peer Node that is a TCP Server.
	TCPClient TransportMode = 0x0001
	// TCPServer: The advertising Node implements the TCP Server mode and SHALL listen for incoming TCP connections.
	TCPServer TransportMode = 0x0002
)
