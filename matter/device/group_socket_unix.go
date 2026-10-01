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

package device

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/cybergarage/go-matter/matter/protocol/group"
	"golang.org/x/sys/unix"
)

// listenGroup opens a socket bound to a group's multicast address on the
// Matter port, which other Matter nodes on the host may share, and joins
// the address on every multicast interface. Bound to the group's address,
// it receives only the group's messages, never the unicast messages of a
// node listening on the Matter port.
func listenGroup(ip net.IP) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				if sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); sockErr != nil {
					return
				}
				sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
			if err != nil {
				return err
			}
			return sockErr
		},
		KeepAlive:       0,
		KeepAliveConfig: net.KeepAliveConfig{Enable: false, Idle: 0, Interval: 0, Count: 0},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp6", net.JoinHostPort(ip.String(), strconv.Itoa(group.Port)))
	if err != nil {
		return nil, err
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("device: not a UDP socket")
	}
	if err := joinMulticast(conn, ip); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// joinMulticast joins an IPv6 multicast group on every interface which is
// up and multicast-capable.
func joinMulticast(conn *net.UDPConn, ip net.IP) error {
	ifis, err := net.Interfaces()
	if err != nil {
		return err
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var mreq syscall.IPv6Mreq
	copy(mreq.Multiaddr[:], ip.To16())
	done := 0
	var lastErr error
	for _, ifi := range ifis {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 {
			continue
		}
		mreq.Interface = uint32(ifi.Index) // nolint: gosec // an interface index
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, &mreq)
		}); err != nil {
			return err
		}
		if sockErr != nil {
			lastErr = fmt.Errorf("%s: %w", ifi.Name, sockErr)
			continue
		}
		done++
	}
	if done == 0 {
		if lastErr == nil {
			lastErr = errors.New("no multicast interface")
		}
		return lastErr
	}
	return nil
}
