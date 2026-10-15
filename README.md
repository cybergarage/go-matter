![](https://img.shields.io/badge/status-Work%20In%20Progress-8A2BE2)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/cybergarage/go-matter)
[![test](https://github.com/cybergarage/go-matter/actions/workflows/make.yml/badge.svg)](https://github.com/cybergarage/go-matter/actions/workflows/make.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/cybergarage/go-matter.svg)](https://pkg.go.dev/github.com/cybergarage/go-matter)
 [![Go Report Card](https://img.shields.io/badge/go%20report-A%2B-brightgreen)](https://goreportcard.com/report/github.com/cybergarage/go-matter) 
 [![codecov](https://codecov.io/gh/cybergarage/go-matter/graph/badge.svg?token=7Y64KS92VD)](https://codecov.io/gh/cybergarage/go-matter)

# go-matter

Matter is an open-source connectivity standard for smart home and IoT (Internet of Things) devices.
`go-matter` is a Go library for building a Matter controller, and `matterctl` is the command which drives it.

> **Bundled third-party test credentials.** `matter/credentials/testcreds` contains the public test attestation credentials of the Matter SDK, [project-chip/connectedhomeip](https://github.com/project-chip/connectedhomeip) (Apache License 2.0): the development DAC and PAI for vendor ID 0xFFF1 and product ID 0x8000, the test PAA, and the example Certification Declaration. They are copied unmodified from commit `d305b0761957c960c26c0841e1b50add2365871d`, with the SDK's `LICENSE` and `NOTICE`. See [matter/credentials/testcreds/certs/README.md](matter/credentials/testcreds/certs/README.md) for the source of each file. They are for development and testing only: their private key is public, and commissioners accept them only in development mode.

## Status

go-matter is a **commissioner (controller)**. It discovers a commissionable device over BLE and mDNS, commissions it onto a fabric, and reads, writes and invokes the clusters of the node afterwards.

**Running as a Matter device is under development.** The `matter/device` package is commissioned over IP by another commissioner such as chip-tool: it advertises itself over mDNS, answers PASE and CASE, attests, and joins the fabric. It serves the clusters of the root node and an On/Off Light with Identify, Groups and Scenes, which chip-tool reads, operates and subscribes to; see [examples/onofflight](examples/onofflight). It has not been verified with Google Home or Amazon Alexa yet. The device role is planned for v1.0.0.

| | Status |
| --- | --- |
| Commissioning and operating a device (commissioner) | Supported |
| Being commissioned, and serving clusters (device) | **In development**: commissioned over IP by chip-tool; the root node clusters and an On/Off Light, with CASE session resumption. No events or Network Commissioning server yet |
| `matterctl` command | Supported |

### What the commissioner supports

- Discovering a commissionable device over BLE and over mDNS, from a QR code payload or a manual pairing code
- Commissioning over BLE (BTP) and over IP: PASE (SPAKE2+), the fail-safe and general commissioning flow, CSR and NOC issuance, and CASE
- Device attestation verification: the DAC → PAI → PAA chain and the Certification Declaration, in a development mode (the default, which also trusts the test credentials of the Matter SDK), a production mode, or none
- A persistent store of the fabric and of the commissioned nodes, so that a node is reachable again after a restart
- A key store for the fabric's private keys, apart from that store: files encrypted with a passphrase, or an HSM, a KMS or a TPM through `crypto.Signer`
- Reconnecting to a commissioned node with CASE, resuming the last session (session resumption) when the node still knows it; subscriptions move over to the new session when the old one fails
- The Interaction Model: Read, Write and Invoke, including the reassembly of a chunked list, and subscriptions to attributes and events, which report changes to a callback and subscribe again when a report is overdue
- Events: reading the events a node keeps, and subscribing to them, with event number filters and timestamps resolved
- The Message Reliability Protocol: acknowledgements and counters
- The Basic Information, Descriptor, General Commissioning, General Diagnostics, Network Commissioning, Operational Credentials, Access Control and On/Off clusters, as a client

### What is not supported yet

- **Certificate revocation is not checked.** Device attestation is verified against a bundled snapshot of the Distributed Compliance Ledger's PAAs and CD signing keys, refreshed monthly; a PAA approved since the snapshot can be added with `WithCommissionerAttestationTrustStore` (`matterctl pairing --paa-trust-store`). `credentials.RevocationChecker` is a hook for a revocation check, which go-matter does not implement yet.
- Thread commissioning: only the Wi-Fi credentials of a device can be set, with `pairing code-wifi` or the Wi-Fi fields of the TUI's Pair device
- Multi-admin: opening a commissioning window on a commissioned node (sending OpenCommissioningWindow) so that another ecosystem can join it
- Timed writes
- User-directed commissioning (UDC), NFC and Wi-Fi PAF commissioning, Joint Fabric (JCM), ICD (intermittently connected device) clients and an OTA provider
- Groups, bindings, scenes and OTA software update
- The clusters which are not listed above
- The session resumption state lives in memory only, so the first `Connect` after a restart, and the first after commissioning, run a full CASE
- Only a few real devices have been commissioned and operated so far, and multi-admin alongside Google Home or Amazon Alexa has not been verified yet
- On macOS, Core Bluetooth may refuse the Matter BLE service of a device (`uuidNotAllowed`); commission such a device over BLE from Linux (BlueZ), or over IP

### Releases

| Version | Scope |
| --- | --- |
| v0.8.0 | The first commissioner release |
| **v0.9.0** | The commissioner completed: attestation validation, subscriptions and events, CASE session resumption, a key store, and the `matterctl tui` controller, verified against a real device |
| v0.9.x | Fixes found against more real devices, and multi-admin alongside Google Home and Amazon Alexa verified |
| v1.0.0 | The device role, and a stable API |

### Progress Overview

#### Packages

| Category | Package | Status | Description |
|----------|---------|--------|-------------|
| Discovery | `ble.btp` | ✅ Implemented | BLE transport protocol (BTP) implementation |
|           | `mdns` | ✅ Implemented | mDNS (Multicast DNS) service discovery |
| Commissioning | `protocol.pase` | ✅ Implemented | Passcode-Authenticated Session Establishment (PASE / SPAKE2+) |
|               | `protocol.case` | ✅ Implemented | Certificate-Authenticated Session Establishment (CASE), with session resumption (Sigma2_Resume) |
|               | `protocol.session` | ✅ Implemented | Secure session management |
|               | `credentials` | ✅ Implemented | Device attestation verification (DAC → PAI → PAA, Certification Declaration), CSR, and CA/NOC chain handling |
|               | `credentials.production` | ✅ Implemented | Bundled snapshot of the DCL's production PAAs and CD signing certificates |
|               | `credentials.dcl` | ✅ Implemented | DCL REST client which refreshes that snapshot (`make update-production-certs`) |
|               | `store` | ✅ Implemented | Persistent fabric and commissionee record store |
|               | `keystore` | ✅ Implemented | Key store for the fabric's private keys: encrypted files, or any `crypto.Signer` (HSM, KMS, TPM) |
| Interaction Model | `protocol.im` | ✅ Implemented | Read/Write/Invoke transactions, incl. chunked list reassembly; attribute and event subscriptions; event reads; exchange multiplexing (`ExchangeMux`) |
|                    | `protocol.mrp` | ✅ Implemented | Message Reliability Protocol (acknowledgement, counters) |
| Clusters | `cluster` | ✅ Implemented | Basic Information, Descriptor, General Commissioning/Diagnostics, Network Commissioning, Operational Credentials, Access Control |
|          | `cluster.onoff` | ✅ Implemented | On/Off cluster client |
| Operation | `cmd.matterctl` | ✅ Implemented | `matterctl` CLI (scan, pairing, per-cluster read/write/invoke, subscriptions, events) and the `matterctl tui` full-screen controller |
| Encoding | `encoding.base38` | ✅ Implemented | Base38 encoding/decoding |
|          | `encoding.qr` | ✅ Implemented | QR code generation |
|          | `encoding.pairing` | ✅ Implemented | Manual pairing code handling |
|          | `encoding.message` | ✅ Implemented | Message Frame Format encoding |
|          | `encoding.tlv` | ✅ Implemented | TLV (Tag-Length-Value) encoding |

#### Related Projects

| Project | Status | Description |
|---------|--------|-------------|
| [go-ble](https://github.com/cybergarage/go-ble) | v0.9.0 (central only) | Go package for Bluetooth Low Energy (BLE) communication |
| [go-mdns](https://github.com/cybergarage/go-mdns) | v1.0.0 | Go package for mDNS (Multicast DNS) and DNS-SD: service discovery and publication |

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

### Device attestation

A commissioner verifies the device attestation of every device it commissions, and refuses one which does not verify with a `credentials.AttestationError`. The mode is set with `WithCommissionerAttestationMode`:

| Mode | Trusts |
| --- | --- |
| `matter.AttestationDevelopment` (default) | The production PAAs and CD signing keys of the DCL, bundled in `credentials/production`, and the test PAA and test CD signing key of the Matter SDK, so certified products and self-made test devices both commission |
| `matter.AttestationProduction` | The production trust anchors only: the test vendor IDs (0xFFF1 to 0xFFF4), development and test Certification Declarations and the SDK's test anchors are rejected |
| `matter.AttestationNone` | Nothing: only the DAC's signature over the attestation elements and the nonce are checked |

```go
commissioner := matter.NewCommissioner(
	matter.WithCommissionerAttestationMode(matter.AttestationProduction),
)
```

PAAs and CD signing certificates of your own are added with `WithCommissionerAttestationTrustStore` and `credentials.LoadAttestationTrustStore`. The library itself never reaches the network for them.

### Subscriptions and events

A node from `Connect` reports the attributes and the events it is subscribed to through a callback. The first report (`Priming`) holds every subscribed attribute; the subscription subscribes again when a report is overdue, and moves to a new session when the node's session fails.

```go
paths := []im.AttributeRequestPath{
	im.NewAttributeRequestPath(1, 0x0006, 0x0000), // On/Off of endpoint 1
}
sub, err := node.(matter.AttributeSubscriber).Subscribe(ctx, paths,
	func(r *im.Report) {
		for _, a := range r.Attributes {
			log.Printf("attribute %v: %v", a.Path, a.Value)
		}
		for _, e := range r.Events {
			log.Printf("event #%d %v at %d", e.EventNumber, e.Path, e.Timestamp)
		}
	},
	im.WithMaxInterval(time.Minute),
	im.WithEvents(im.NewEventRequestPath(0, 0x0028, 0x0000)), // StartUp of Basic Information
)
if err != nil {
	return err
}
defer sub.Close()
```

The events a node keeps are read with `EventReader`:

```go
events, err := node.(matter.EventReader).ReadEvents(
	[]im.EventRequestPath{im.NewEventRequestPath(0, 0x0028, 0x0000)},
)
```

### Reconnection

A node from `Connect` lives until it is closed. When a request finds its session failed, it connects again before the request, resuming the last CASE session when the node still knows it (session resumption) and running a full CASE when not; the request itself is not sent again. `Reconnector` does the same on demand:

```go
if r, ok := node.(matter.Reconnector); ok {
	if err := r.Reconnect(ctx); err != nil {
		return err
	}
	log.Printf("session resumed: %v", r.Resumed())
}
```

### Key store

By default, the fabric's root CA key and the commissioner's operational key are kept in the fabric record of the store. `WithCommissionerKeyStore` keeps them in a `keystore.KeyStore` instead: encrypted files, or an HSM, a cloud KMS or a TPM through `crypto.Signer`.

```go
ks, err := keystore.NewFileKeyStore(dir, keystore.WithPassphrase(passphrase))
if err != nil {
	return err
}
commissioner := matter.NewCommissioner(matter.WithCommissionerKeyStore(ks))
```

`Start` moves the keys an existing fabric record holds into the key store. See [Commissioner Persistent Store](doc/commissioner-store.md#key-store).

## Command

`matterctl` commissions and operates a device from a terminal. See the [command reference](doc/matterctl.md).

```
$ matterctl scan
$ matterctl pairing code 1 MT:-24J0AFN00KA0648G00
$ matterctl pairing code-wifi 1 MT:-24J0AFN00KA0648G00 <ssid> <password>
$ matterctl basicinformation read 1 0
$ matterctl onoff on 1 1
$ matterctl any read 0x0006 0x0000 1 1
$ matterctl any subscribe 0x0006 '*' 1 1
$ matterctl any read-events 0x0028 '*' 1 0
$ matterctl any subscribe-events 0x0028 '*' 1 0
$ matterctl reset
```

`matterctl pairing` takes `--attestation development|production|none`, and `--paa-trust-store` / `--cd-trust-store` for trust anchors of your own. The fabric's private keys are kept in an encrypted file key store when the environment variable `MATTER_CTL_KEY_STORE` names its directory and `MATTER_CTL_KEY_STORE_PASSPHRASE` is set; both are read from the environment only.

### Full-screen controller

Run `make tui` for the `matterctl tui` dashboard on real devices, with the
store `~/.matterctl`, or `make tui-debug` for the same with a debug log;
`--offline` (`make tui TUI_ARGS=--offline`) runs a fictional fixture instead.
Live use requires a valid commissioner fabric, restored from the selected
store or explicitly created in the UI. Network operations
require UI confirmation. It supports saved-device menus, manual/QR pairing
forms with optional Wi-Fi credentials for a device found over BLE, an inspect
of the node right after pairing, Descriptor inspection, selected read/On-Off
controls and a log. See [scope, keys, screenshots and verification](doc/matterctl-tui.md).

# User Guides

- Operation
  - [matterctl](doc/matterctl.md)
- Commissioner
  - [Commissioner Persistent Store](doc/commissioner-store.md)
- Device
  - [Device (in development)](doc/device.md)
  - [Device Persistent Store](doc/device-store.md)


## References

- [Matter](https://buildwithmatter.com/)
    - [Matter 1.5 Standard Namespace Specification](https://csa-iot.org/developer-resource/specifications-download-request/)
    - [Matter 1.5 Device Library Specification](https://csa-iot.org/developer-resource/specifications-download-request/)
    - [Matter 1.5 Core Specification](https://csa-iot.org/developer-resource/specifications-download-request/)
    - [Matter 1.5 Application Cluster Specification](https://csa-iot.org/developer-resource/specifications-download-request/)

### Versioned metadata catalog

The initial offline [`matter/datamodel`](matter/datamodel) catalog provides
version-pinned SDK device/cluster/attribute/command metadata. See
[source licensing, coverage, regeneration and API](doc/matter-definition-db.md).
It does not enable new device operations or change the library's protocol target.
