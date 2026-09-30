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

package cluster

import (
	"github.com/cybergarage/go-matter/matter/protocol/im"
)

// Endpoint is where a cluster server registers its attributes and
// commands; *device.Endpoint is one.
type Endpoint interface {
	HandleAttribute(cluster im.ClusterID, attribute im.AttributeID, r im.AttributeReader, opts ...im.HandlerOption)
	HandleAttributeWrite(cluster im.ClusterID, attribute im.AttributeID, h im.AttributeWriteHandler, opts ...im.HandlerOption)
	HandleCommand(cluster im.ClusterID, command im.CommandID, h im.CommandHandler, opts ...im.HandlerOption)
	NotifyAttributeChanged(cluster im.ClusterID, attribute im.AttributeID)
}
