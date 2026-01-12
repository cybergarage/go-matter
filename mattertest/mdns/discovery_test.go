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

package mdns

import (
	"context"
	"testing"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter/mdns"
)

func TestDiscoverer(t *testing.T) {
	log.SetSharedLogger(log.NewStdoutLogger(log.LevelInfo))

	disc := mdns.NewDiscoverer()

	err := disc.Start()
	if err != nil {
		t.Error(err)
		return
	}

	query := mdns.NewQuery(
		mdns.WithQueryService(mdns.CommissionableNodeService),
	)

	ctx, cancel := context.WithDeadline(
		context.Background(),
		time.Now().Add(1*time.Second),
	)
	defer cancel()

	nodes, err := disc.Search(ctx, query)
	if err != nil {
		t.Error(err)
		return
	}

	for _, node := range nodes {
		log.Infof("Discovered Node: %+v", node)
	}

	err = disc.Stop()
	if err != nil {
		t.Error(err)
		return
	}
}
