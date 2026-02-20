![](https://img.shields.io/badge/status-Work%20In%20Progress-8A2BE2)
![](https://workers-hub.zoom.us/j/89428436853?pwd=Qm41UHlJNW1LazN3RFVzV1dwM09udz09&from=addon)
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
| Discovery | `ble.btp` | ✅ Under verification | BLE transport protocol implementation |
|           | `mdns` | ✅ Implemented | mDNS (Multicast DNS) service discovery |
| Commissioning |`pase` | 🚧 In progress | Passcode-Authenticated Session Establishment (PASE) implementation |
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


## References

- [Matter](https://buildwithmatter.com/)
    - [Matter 1.5 Standard Namespace Specification](https://csa-iot.org/developer-resource/specifications-download-request/)
    - [Matter 1.5 Device Library Specification](https://csa-iot.org/developer-resource/specifications-download-request/)
    - [Matter 1.5 Core Specification](https://csa-iot.org/developer-resource/specifications-download-request/)
    - [Matter 1.5 Application Cluster Specification](https://csa-iot.org/developer-resource/specifications-download-request/)
