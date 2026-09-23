![](https://img.shields.io/badge/status-Work%20In%20Progress-8A2BE2)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/cybergarage/go-matter)
[![test](https://github.com/cybergarage/go-matter/actions/workflows/make.yml/badge.svg)](https://github.com/cybergarage/go-matter/actions/workflows/make.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/cybergarage/go-matter.svg)](https://pkg.go.dev/github.com/cybergarage/go-matter)
 [![Go Report Card](https://img.shields.io/badge/go%20report-A%2B-brightgreen)](https://goreportcard.com/report/github.com/cybergarage/go-matter) 
 [![codecov](https://codecov.io/gh/cybergarage/go-matter/graph/badge.svg?token=7Y64KS92VD)](https://codecov.io/gh/cybergarage/go-matter)

# go-matter

Matter is an open-source connectivity standard for smart home and IoT (Internet of Things) devices.
`go-matter` is a Go library for building a Matter controller, and `matterctl` is the command which drives it.

**Note:** 🌱 This is a spare-time hobby project, so progress may be slow and changes may appear irregular. Thank you for your patience 🙂

## Status

go-matter is a **commissioner (controller)**. It discovers a commissionable device over BLE and mDNS, commissions it onto a fabric, and reads, writes and invokes the clusters of the node afterwards.

**Running as a Matter device is not implemented.** go-matter cannot be commissioned by another controller, and it serves no cluster of its own. The device role is planned for v1.0.0.

| | Status |
| --- | --- |
| Commissioning and operating a device (commissioner) | Supported |
| Being commissioned, and serving clusters (device) | **Not implemented** |
| `matterctl` command | Supported |

### What the commissioner supports

- Discovering a commissionable device over BLE and over mDNS, from a QR code payload or a manual pairing code
- Commissioning over BLE (BTP) and over IP: PASE (SPAKE2+), the fail-safe and general commissioning flow, CSR and NOC issuance, and CASE
- A persistent store of the fabric and of the commissioned nodes, so that a node is reachable again after a restart
- Reconnecting to a commissioned node with a fresh CASE handshake
- The Interaction Model: Read, Write and Invoke, including the reassembly of a chunked list
- The Message Reliability Protocol: acknowledgements and counters
- The Basic Information, Descriptor, General Commissioning, General Diagnostics, Network Commissioning, Operational Credentials, Access Control and On/Off clusters, as a client

### What is not supported yet

- **The device attestation chain of trust is not validated.** The attestation exchange runs and its response is parsed, but the certificate chain is accepted without being verified against the Distributed Compliance Ledger. Do not rely on go-matter to reject an untrusted device.
- Interaction Model subscriptions: an attribute is read on demand, and a change cannot be reported to the controller
- Thread commissioning: only the Wi-Fi credentials of a device can be set, with `pairing code-wifi`
- Groups, bindings, scenes and OTA software update
- Session resumption: every reconnect is a full CASE handshake
- The clusters which are not listed above

### Releases

| Version | Scope |
| --- | --- |
| **v0.8.0** | The commissioner, with the gaps which are listed above |
| v0.9.0 | The commissioner completed: attestation validation, subscriptions, and the clusters verified against real devices |
| v1.0.0 | The device role, and a stable API |

### Progress Overview

#### Packages

| Category | Package | Status | Description |
|----------|---------|--------|-------------|
| Discovery | `ble.btp` | ✅ Implemented | BLE transport protocol (BTP) implementation |
|           | `mdns` | ✅ Implemented | mDNS (Multicast DNS) service discovery |
| Commissioning | `protocol.pase` | ✅ Implemented | Passcode-Authenticated Session Establishment (PASE / SPAKE2+) |
|               | `protocol.case` | ✅ Implemented | Certificate-Authenticated Session Establishment (CASE) |
|               | `protocol.session` | ✅ Implemented | Secure session management |
|               | `credentials` | ✅ Under verification | Attestation, CSR, and CA/NOC chain handling (attestation chain-of-trust validation is intentionally skipped for now) |
|               | `store` | ✅ Implemented | Persistent fabric and commissionee record store |
| Interaction Model | `protocol.im` | ✅ Implemented | Read/Write/Invoke Interaction Model transactions, incl. chunked list reassembly |
|                    | `protocol.mrp` | ✅ Implemented | Message Reliability Protocol (acknowledgement, counters) |
| Clusters | `cluster` | ✅ Implemented | Basic Information, Descriptor, General Commissioning/Diagnostics, Network Commissioning, Operational Credentials, Access Control |
|          | `cluster.onoff` | ✅ Under verification | On/Off cluster client (not yet exercised against a real device) |
| Operation | `cmd.matterctl` | 🚧 In progress | `matterctl` CLI (pairing, scan, per-cluster read/write/invoke) |
| Encoding | `encoding.base38` | ✅ Implemented | Base38 encoding/decoding |
|          | `encoding.qr` | ✅ Implemented | QR code generation |
|          | `encoding.pairing` | ✅ Implemented | Manual pairing code handling |
|          | `encoding.message` | ✅ Implemented | Message Frame Format encoding |
|          | `encoding.tlv` | ✅ Implemented | TLV (Tag-Length-Value) encoding |

#### Related Projects

| Project | Status | Description |
|---------|--------|-------------|
| [go-ble](https://github.com/cybergarage/go-ble) | v0.9.0 (central only) | Go package for Bluetooth Low Energy (BLE) communication |
| [go-mdns](https://github.com/cybergarage/go-mdns) | v0.9.0 (client only) | Go package for mDNS (Multicast DNS) service discovery |


## Install

```
go get -u github.com/cybergarage/go-matter
```

The `matterctl` command is installed with:

```
go install github.com/cybergarage/go-matter/cmd/matterctl@latest
```

## Usage

A commissioner is started once, and it then discovers, commissions and reaches the devices of its fabric.

```go
commissioner := matter.NewCommissioner()
if err := commissioner.Start(); err != nil {
	return err
}
defer commissioner.Stop()

// The payload comes from the manual pairing code, or from the QR code, of
// the device.
payload, err := encoding.NewPairingCodeFromString(code)
if err != nil {
	return err
}

commissionee, err := commissioner.Commission(context.Background(), payload)
if err != nil {
	return err
}

nodeID, _ := commissionee.NodeID()
```

A commissioned node is reached again through the store, without commissioning it a second time:

```go
node, err := commissioner.Connect(context.Background(), nodeID)
if err != nil {
	return err
}

res, err := node.ReadAttribute(endpointID, clusterID, attributeID)
```

Commissioning bounds the whole PASE-through-CASE exchange with a single deadline, which defaults to `DefaultCommissioningTimeout` (120 seconds): a device commits its new fabric to persistent storage and then re-advertises itself over mDNS before CASE can start, and a shorter deadline expires in the middle of that.

## Command

`matterctl` commissions and operates a device from a terminal. See the [command reference](doc/matterctl.md).

```
$ matterctl scan
$ matterctl pairing code 1 MT:-24J0AFN00KA0648G00
$ matterctl pairing code-wifi 1 MT:-24J0AFN00KA0648G00 <ssid> <password>
$ matterctl basicinformation read 1 0
$ matterctl onoff on 1 1
$ matterctl any read 0x0006 0x0000 1 1
$ matterctl reset
```

# User Guides

- Operation
  - [matterctl](doc/matterctl.md)
- Commissioner
  - [Commissioner Persistent Store](doc/commissioner-store.md)


## References

- [Matter](https://buildwithmatter.com/)
    - [Matter 1.5 Standard Namespace Specification](https://csa-iot.org/developer-resource/specifications-download-request/)
    - [Matter 1.5 Device Library Specification](https://csa-iot.org/developer-resource/specifications-download-request/)
    - [Matter 1.5 Core Specification](https://csa-iot.org/developer-resource/specifications-download-request/)
    - [Matter 1.5 Application Cluster Specification](https://csa-iot.org/developer-resource/specifications-download-request/)
