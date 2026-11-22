# What go-matter supports

go-matter is a Matter **commissioner (controller)**. This page lists what it supports and what it does not yet. See the [README](../README.md) for an overview, and [CHANGELOG.md](../CHANGELOG.md) for the history of each release.

## Roles

go-matter is a **commissioner (controller)**. It discovers a commissionable device over BLE and mDNS, commissions it onto a fabric, and reads, writes and invokes the clusters of the node afterwards.

**Running as a Matter device is under development.** The `matter/device` package is commissioned over IP by another commissioner such as chip-tool: it advertises itself over mDNS, answers PASE and CASE, attests, and joins the fabric. It serves the clusters of the root node and an On/Off Light with Identify, Groups and Scenes, which chip-tool reads, operates and subscribes to; see [examples/onofflight](../examples/onofflight). It has not been verified with Google Home or Amazon Alexa yet. The device role is planned for v1.1.0 and later; v1.0.0 completes the commissioner, with a stable API (see [API stability](packages.md#api-stability)).

| | Status |
| --- | --- |
| Commissioning and operating a device (commissioner) | Supported |
| Being commissioned, and serving clusters (device) | **In development**: commissioned over IP by chip-tool; the root node clusters and an On/Off Light, with CASE session resumption. No events or Network Commissioning server yet |
| `matterctl` command | Supported |

## What the commissioner supports

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
- Multi-admin: opening a commissioning window on a commissioned node (Administrator Commissioning, with a fresh setup code, QR code and manual pairing code) so that another ecosystem adds it too, and commissioning a device another ecosystem shares; verified with Google Home
- Commissioning progress, and why a device could not join its Wi-Fi network

## Verified with

- **Ecosystems (multi-admin).** Google Home on iOS, in both directions: a node go-matter shared with a pairing window was added to Google Home, and a device Google Home shared (*Linked Matter apps & services*) was commissioned over IP; both controlled it. Amazon Alexa, Apple Home, SmartThings and Home Assistant are not verified yet.
- **Devices.** Two Wi-Fi light bulbs of different vendors, commissioned over BLE with Wi-Fi credentials and over IP, and operated (on/off, level, color temperature, subscriptions). In CI, `chip-tool` of the Matter SDK commissions the device role (`matter/device`) over the network.
- **Platforms.** Linux with BlueZ, for BLE and mDNS. macOS builds and runs, and CI tests the full-screen controller there; Core Bluetooth may refuse a device's Matter BLE service (see below).

## What is not supported yet

- **Certificate revocation is not checked.** Device attestation is verified against a bundled snapshot of the Distributed Compliance Ledger's PAAs and CD signing keys, refreshed monthly; a PAA approved since the snapshot can be added with `WithCommissionerAttestationTrustStore` (`matterctl pairing --paa-trust-store`). `credentials.RevocationChecker` is a hook for a revocation check, which go-matter does not implement yet.
- Thread commissioning: only the Wi-Fi credentials of a device can be set, with `pairing code-wifi` or the Wi-Fi fields of the TUI's Pair device
- Timed writes
- User-directed commissioning (UDC), NFC and Wi-Fi PAF commissioning, Joint Fabric (JCM), ICD (intermittently connected device) clients and an OTA provider
- Groups, bindings, scenes and OTA software update
- The clusters which are not listed above
- The session resumption state lives in memory only, so the first `Connect` after a restart, and the first after commissioning, run a full CASE
- Only a few real devices have been commissioned and operated so far; multi-admin has been verified with Google Home, not yet with Amazon Alexa or Apple Home
- Devices which support only non-concurrent connection (BLE and Wi-Fi not at once) are not commissioned yet
- On macOS, Core Bluetooth may refuse the Matter BLE service of a device (`uuidNotAllowed`); commission such a device over BLE from Linux (BlueZ), or over IP
