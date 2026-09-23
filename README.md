![](https://img.shields.io/badge/status-Work%20In%20Progress-8A2BE2)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/cybergarage/go-matter)
[![test](https://github.com/cybergarage/go-matter/actions/workflows/make.yml/badge.svg)](https://github.com/cybergarage/go-matter/actions/workflows/make.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/cybergarage/go-matter.svg)](https://pkg.go.dev/github.com/cybergarage/go-matter)
 [![Go Report Card](https://img.shields.io/badge/go%20report-A%2B-brightgreen)](https://goreportcard.com/report/github.com/cybergarage/go-matter) 
 [![codecov](https://codecov.io/gh/cybergarage/go-matter/graph/badge.svg?token=7Y64KS92VD)](https://codecov.io/gh/cybergarage/go-matter)

# go-matter

Matter is an open-source connectivity standard for smart home and IoT (Internet of Things) devices.
`go-matter` is a Go library for develping Matter applications and devices.

**Note:** 🌱 This is a spare-time hobby project, so progress may be slow and changes may appear irregular. Thank you for your patience 🙂

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
| [go-ble](https://github.com/cybergarage/go-ble) | 🚧 In progress | Go package for Bluetooth Low Energy (BLE) communication |
| [go-mdns](https://github.com/cybergarage/go-mdns) | 🚧 In progress | Go package for mDNS (Multicast DNS) service discovery |


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
