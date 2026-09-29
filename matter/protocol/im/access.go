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

package im

// Privilege is an Access Control privilege (Matter Core 9.10.5.2). A
// higher privilege includes the lower ones, except that ProxyView is
// included only by Administer.
type Privilege uint8

const (
	PrivilegeView       Privilege = 1
	PrivilegeProxyView  Privilege = 2
	PrivilegeOperate    Privilege = 3
	PrivilegeManage     Privilege = 4
	PrivilegeAdminister Privilege = 5
)

// Grants reports whether holding p grants required (9.10.5.2).
func (p Privilege) Grants(required Privilege) bool {
	switch p {
	case PrivilegeAdminister:
		return true
	case PrivilegeProxyView:
		return required == PrivilegeProxyView || required == PrivilegeView
	case PrivilegeManage, PrivilegeOperate, PrivilegeView:
		return required != PrivilegeProxyView && required <= p
	default:
		return false
	}
}

// Default privileges a handler requires unless WithPrivilege says
// otherwise (9.10.5.2): reading an attribute needs View, and invoking a
// command Operate.
const (
	DefaultReadPrivilege   = PrivilegeView
	DefaultInvokePrivilege = PrivilegeOperate
)

// HandlerOption configures a command handler or an attribute reader.
type HandlerOption func(*handlerOptions)

type handlerOptions struct {
	privilege Privilege
}

// WithPrivilege sets the privilege the handler requires of the subject of
// a request.
func WithPrivilege(p Privilege) HandlerOption {
	return func(o *handlerOptions) {
		o.privilege = p
	}
}

func newHandlerOptions(defaultPrivilege Privilege, opts []HandlerOption) handlerOptions {
	o := handlerOptions{privilege: defaultPrivilege}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// AccessRequest is what an AccessChecker decides on: whether the subject
// of Session may act on the cluster at the endpoint with Privilege
// (9.10.4).
type AccessRequest struct {
	Session   SecureSession
	Endpoint  EndpointID
	Cluster   ClusterID
	Privilege Privilege
}

// AccessChecker reports whether an AccessRequest is granted. A Server
// without one grants every request.
type AccessChecker func(req AccessRequest) bool
