package matter

import (
	"context"
	"fmt"
	"net"
	"time"

	mdnspkg "github.com/cybergarage/go-matter/matter/mdns"
)

type operationalUDPTransport struct {
	conn    *net.UDPConn
	readBuf []byte
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
	if err := conn.SetWriteDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	return &operationalUDPTransport{
		conn:    conn,
		readBuf: make([]byte, 1500),
	}, nil
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
					if iface.Flags&net.FlagUp == 0 {
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

func (t *operationalUDPTransport) Transmit(_ context.Context, b []byte) error {
	n, err := t.conn.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return fmt.Errorf("udp short write: %d/%d", n, len(b))
	}
	return nil
}

func (t *operationalUDPTransport) Receive(_ context.Context) ([]byte, error) {
	n, err := t.conn.Read(t.readBuf)
	if err != nil {
		return nil, err
	}
	return t.readBuf[:n], nil
}

func (t *operationalUDPTransport) Close() error {
	return t.conn.Close()
}
