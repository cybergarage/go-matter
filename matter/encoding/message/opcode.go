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

package message

// Opcode represents a message protocol opcode.
// 4.4.3.2. Protocol Opcode (8 bits).
type Opcode uint8

// 4.11.1. Secure Channel Protocol Messages.
const (
	MsgCounterSyncReq            Opcode = 0x00
	MsgCounterSyncRsp            Opcode = 0x01
	MRPStandaloneAcknowledgement Opcode = 0x10
	PBKDFParamRequest            Opcode = 0x20
	PBKDFParamResponse           Opcode = 0x21
	PASEPake1                    Opcode = 0x22
	PASEPake2                    Opcode = 0x23
	PASEPake3                    Opcode = 0x24
	CASESigma1                   Opcode = 0x30
	CASESigma2                   Opcode = 0x31
	CASESigma3                   Opcode = 0x32
	CASESigma2Resume             Opcode = 0x33
	StatusReport                 Opcode = 0x40
	ICDCheckInMessage            Opcode = 0x50
)

// IsMsgCounterSyncReq returns true if the opcode is MsgCounterSyncReq.
func (o Opcode) IsMsgCounterSyncReq() bool {
	return o == MsgCounterSyncReq
}

// IsMsgCounterSyncRsp returns true if the opcode is MsgCounterSyncRsp.
func (o Opcode) IsMsgCounterSyncRsp() bool {
	return o == MsgCounterSyncRsp
}

// IsMRPStandaloneAcknowledgement returns true if the opcode is MRPStandaloneAcknowledgement.
func (o Opcode) IsMRPStandaloneAcknowledgement() bool {
	return o == MRPStandaloneAcknowledgement
}

// IsPBKDFParamRequest returns true if the opcode is PBKDFParamRequest.
func (o Opcode) IsPBKDFParamRequest() bool {
	return o == PBKDFParamRequest
}

// IsPBKDFParamResponse returns true if the opcode is PBKDFParamResponse.
func (o Opcode) IsPBKDFParamResponse() bool {
	return o == PBKDFParamResponse
}

// IsPASEPake1 returns true if the opcode is PASEPake1.
func (o Opcode) IsPASEPake1() bool {
	return o == PASEPake1
}

// IsPASEPake2 returns true if the opcode is PASEPake2.
func (o Opcode) IsPASEPake2() bool {
	return o == PASEPake2
}

// IsPASEPake3 returns true if the opcode is PASEPake3.
func (o Opcode) IsPASEPake3() bool {
	return o == PASEPake3
}

// IsCASESigma1 returns true if the opcode is CASESigma1.
func (o Opcode) IsCASESigma1() bool {
	return o == CASESigma1
}

// IsCASESigma2 returns true if the opcode is CASESigma2.
func (o Opcode) IsCASESigma2() bool {
	return o == CASESigma2
}

// IsCASESigma3 returns true if the opcode is CASESigma3.
func (o Opcode) IsCASESigma3() bool {
	return o == CASESigma3
}

// IsCASESigma2Resume returns true if the opcode is CASESigma2Resume.
func (o Opcode) IsCASESigma2Resume() bool {
	return o == CASESigma2Resume
}

// IsStatusReport returns true if the opcode is StatusReport.
func (o Opcode) IsStatusReport() bool {
	return o == StatusReport
}

// IsICDCheckInMessage returns true if the opcode is ICDCheckInMessage.
func (o Opcode) IsICDCheckInMessage() bool {
	return o == ICDCheckInMessage
}

// 10.2.1. IM Protocol Messages.
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

// IsStatusResponseMessage returns true if the opcode is StatusResponseMessage.
func (o Opcode) IsStatusResponseMessage() bool {
	return o == StatusResponseMessage
}

// IsReadRequestMessage returns true if the opcode is ReadRequestMessage.
func (o Opcode) IsReadRequestMessage() bool {
	return o == ReadRequestMessage
}

// IsSubscribeRequestMessage returns true if the opcode is SubscribeRequestMessage.
func (o Opcode) IsSubscribeRequestMessage() bool {
	return o == SubscribeRequestMessage
}

// IsSubscribeResponseMessage returns true if the opcode is SubscribeResponseMessage.
func (o Opcode) IsSubscribeResponseMessage() bool {
	return o == SubscribeResponseMessage
}

// IsReportDataMessage returns true if the opcode is ReportDataMessage.
func (o Opcode) IsReportDataMessage() bool {
	return o == ReportDataMessage
}

// IsWriteRequestMessage returns true if the opcode is WriteRequestMessage.
func (o Opcode) IsWriteRequestMessage() bool {
	return o == WriteRequestMessage
}

// IsWriteResponseMessage returns true if the opcode is WriteResponseMessage.
func (o Opcode) IsWriteResponseMessage() bool {
	return o == WriteResponseMessage
}

// IsInvokeRequestMessage returns true if the opcode is InvokeRequestMessage.
func (o Opcode) IsInvokeRequestMessage() bool {
	return o == InvokeRequestMessage
}

// IsInvokeResponseMessage returns true if the opcode is InvokeResponseMessage.
func (o Opcode) IsInvokeResponseMessage() bool {
	return o == InvokeResponseMessage
}

// IsTimedRequestMessage returns true if the opcode is TimedRequestMessage.
func (o Opcode) IsTimedRequestMessage() bool {
	return o == TimedRequestMessage
}
