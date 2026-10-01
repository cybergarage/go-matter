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

//go:build unix

package group

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// transmitMulticast sends a packet to a group's address out of every
// interface which is up and multicast-capable, as a group's members may
// be on any of the node's links. It succeeds if it was sent out of one.
func transmitMulticast(addr *net.UDPAddr, packet []byte) error {
	ifis, err := net.Interfaces()
	if err != nil {
		return err
	}
	sent := 0
	var lastErr error
	for _, ifi := range ifis {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		if err := sendOnInterface(ifi, addr, packet); err != nil {
			lastErr = fmt.Errorf("%s: %w", ifi.Name, err)
			continue
		}
		sent++
	}
	if sent == 0 {
		if lastErr == nil {
			lastErr = errors.New("no multicast interface")
		}
		return fmt.Errorf("group: send to %s: %w", addr.IP, lastErr)
	}
	return nil
}

func sendOnInterface(ifi net.Interface, addr *net.UDPAddr, packet []byte) error {
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0, Zone: ""})
	if err != nil {
		return err
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, ifi.Index)
	}); err != nil {
		return err
	}
	if sockErr != nil {
		return sockErr
	}
	_, err = conn.WriteToUDP(packet, addr)
	return err
}
