package matter

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/cybergarage/go-matter/matter/io"
	mdnspkg "github.com/cybergarage/go-matter/matter/mdns"
)

type operationalUDPTransport struct {
	conn *net.UDPConn
	// maxDeadline is the outer bound (from the ctx given to
	// newOperationalUDPTransport, or DefaultCommissioningTimeout if it had
	// none) that no per-call deadline may exceed, no matter what a caller's
	// ctx says — see effectiveDeadline.
	maxDeadline time.Time
	readBuf     []byte
}

func newOperationalUDPTransport(ctx context.Context, node mdnspkg.CommissionableNode) (*operationalUDPTransport, error) {
	addr, port, zone, err := lookupOperationalAddrPort(node)
	if err != nil {
		return nil, err
	}
	remote := &net.UDPAddr{
		IP:   addr,
		Port: port,
		Zone: zone,
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DefaultCommissioningTimeout)
	}
	return &operationalUDPTransport{
		conn:        conn,
		maxDeadline: deadline,
		readBuf:     make([]byte, 1500),
	}, nil
}

// effectiveDeadline returns the earlier of ctx's own deadline (if any) and
// t.maxDeadline, so a caller can bound a single Transmit/Receive call to a
// short per-attempt window (e.g. for retrying a lost packet) without ever
// extending the connection past the deadline it was opened with.
func (t *operationalUDPTransport) effectiveDeadline(ctx context.Context) time.Time {
	deadline := t.maxDeadline
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	return deadline
}

func lookupOperationalAddrPort(node mdnspkg.CommissionableNode) (net.IP, int, string, error) {
	port, ok := node.Port()
	if !ok {
		return nil, 0, "", fmt.Errorf("no operational port found")
	}
	addrs, ok := node.Addresses()
	if !ok || len(addrs) == 0 {
		return nil, 0, "", fmt.Errorf("no operational addresses found")
	}
	for _, addr := range addrs {
		if addr.To4() == nil && addr.IsLinkLocalUnicast() {
			ifaces, err := net.Interfaces()
			if err == nil {
				for _, iface := range ifaces {
					// Skip down or loopback interfaces; see the matching
					// comment in device_mdns.go's lookupAddrPort.
					if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
						continue
					}
					ifaceAddrs, err := iface.Addrs()
					if err != nil {
						continue
					}
					for _, ifaceAddr := range ifaceAddrs {
						ipNet, ok := ifaceAddr.(*net.IPNet)
						if !ok {
							continue
						}
						if ipNet.IP.To4() == nil && ipNet.IP.IsLinkLocalUnicast() {
							return addr, port, iface.Name, nil
						}
					}
				}
			}
			return addr, port, "", nil
		}
	}
	for _, addr := range addrs {
		if addr.To4() == nil {
			return addr, port, "", nil
		}
	}
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			return ipv4, port, "", nil
		}
	}
	return nil, 0, "", fmt.Errorf("no suitable operational address found")
}

func (t *operationalUDPTransport) Transmit(ctx context.Context, b []byte) error {
	if err := t.conn.SetWriteDeadline(t.effectiveDeadline(ctx)); err != nil {
		return err
	}
	n, err := t.conn.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("udp short write: %d/%d", n, len(b))
	}
	return nil
}

func (t *operationalUDPTransport) Receive(ctx context.Context) ([]byte, error) {
	if err := t.conn.SetReadDeadline(t.effectiveDeadline(ctx)); err != nil {
		return nil, err
	}
	n, err := t.conn.Read(t.readBuf)
	if err != nil {
		return nil, err
	}
	return t.readBuf[:n], nil
}

func (t *operationalUDPTransport) Close() error {
	return t.conn.Close()
}

// remoteAddrProvider is implemented by transports (e.g. *mDNSDevice) that can
// report the peer address their underlying connection is already dialed to.
type remoteAddrProvider interface {
	RemoteAddr() net.Addr
}

// resolveOperationalTransport decides how to reach node for CASE: if
// paseTransport (the connection PASE/commissioning already used) is dialed
// to an address that's also one of node's operational addresses, it's reused
// directly instead of opening a second connection.
//
// This matters because a real device was observed responding instantly and
// reliably to every single PASE-phase message, then never responding at all
// — confirmed at the packet-capture level, not just a client-side read
// timeout — to CASE Sigma1 sent from a freshly dialed UDP socket (a new
// local/ephemeral port) to that exact same peer address. connectedhomeip's
// own Transport::UDP binds a single local endpoint once and reuses it for
// every peer and session for the life of the controller
// (src/transport/raw/UDP.h); this codebase instead opened an independent
// socket per logical connection (one for the commissionable-node PASE phase
// in device_mdns.go, a separate one here for the operational/CASE phase),
// which — for whatever reason on the real device's network stack — the
// device did not treat as a continuation of the same peer. Reusing the
// existing connection when it already points at the right address matches
// the one-shared-endpoint model and avoids the new-source-port problem
// entirely; a genuinely different operational address (e.g. BLE-to-WiFi
// commissioning, where PASE never had a UDP connection at all) still falls
// through to dialing a new one exactly as before.
func resolveOperationalTransport(ctx context.Context, node mdnspkg.CommissionableNode, paseTransport io.Transport) (io.Transport, error) {
	if reusable, ok := paseTransport.(remoteAddrProvider); ok {
		if paseAddr, ok := reusable.RemoteAddr().(*net.UDPAddr); ok && paseAddr != nil {
			if addrs, ok := node.Addresses(); ok {
				port, hasPort := node.Port()
				for _, addr := range addrs {
					if hasPort && port != paseAddr.Port {
						continue
					}
					if addr.Equal(paseAddr.IP) {
						return paseTransport, nil
					}
				}
			}
		}
	}
	return newOperationalUDPTransport(ctx, node)
}
