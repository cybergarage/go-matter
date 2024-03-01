// Copyright (C) 2024 The go-matter Authors All rights reserved.
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

/*
matter-browse is a search utility for mDNS protocol.

	NAME
	matter-browse

	SYNOPSIS
	matter-browse [OPTIONS]

	matter-browse is a search utility for Matter commissionees.

	RETURN VALUE
	  Return EXIT_SUCCESS or EXIT_FAILURE
*/
package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter"
	"github.com/cybergarage/go-mdns/mdns"
)

func main() {
	verbose := flag.Bool("v", false, "Enable verbose messages")
	debug := flag.Bool("d", false, "Enable debug messages")
	flag.Parse()

	// Setup logger

	if *verbose {
		log.SetSharedLogger(log.NewStdoutLogger(log.LevelTrace))
	}
	if *debug {
		log.SetSharedLogger(log.NewStdoutLogger(log.LevelDebug))
	}

	// Start a controller for Echonet Lite node

	client := matter.NewCommissioner()

	if *verbose {
		client.SetListener(client)
	}

	err := client.Start()
	if err != nil {
		return
	}

	defer client.Stop()

	// err = client.Query(mdns.NewQueryWithService(mdns.AutomaticBrowsingService))
	// if err != nil {
	// 	return
	// }

	services := []string{
		"_services._dns-sd._udp",
		"_rdlink._tcp",
		"_companion - link._tcp",
	}

	err = client.Query(mdns.NewQueryWithServices(services))
	if err != nil {
		return
	}

	// Wait node responses in the local network

	time.Sleep(time.Second * 10)

	// Output all found nodes

	for n, srv := range client.Services() {
		fmt.Printf("[%d] %s\n", n, srv.String())
	}
}
