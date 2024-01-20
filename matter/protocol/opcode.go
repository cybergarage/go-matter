// Copyright (C) 2024 The go-matter Authors. All rights reserved.
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

package protocol

// Opcode represents a message opcode.
type Opcode uint8

const (
	StatusResponseMessage    Opcode = 0x01
	ReadRequestMessage       Opcode = 0x02
	SubscribeRequestMessage  Opcode = 0x03
	SubscribeResponseMessage Opcode = 0x04
	ReportDataMessage        Opcode = 0x05
	WriteRequestMessage      Opcode = 0x06
	WriteResponseMessage     Opcode = 0x07
	InvokeRequestMessage     Opcode = 0x08
	InvokeResponseMessage    Opcode = 0x09
	TimedRequestMessage      Opcode = 0x0A
)
