# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-09-23

The first tagged release. go-matter is a commissioner: it commissions a Matter device onto a fabric and operates it afterwards. Running as a Matter device is not implemented, and it is planned for v1.0.0.

### Added

- **Discovery**: a commissionable device is found over BLE and over mDNS, from a manual pairing code or a QR code payload.
- **Commissioning** over BLE (BTP) and over IP: PASE (SPAKE2+), the fail-safe and general commissioning flow, CSR and NOC issuance, and CASE. The whole exchange is bounded by a single deadline, because a device commits its new fabric to persistent storage and re-advertises itself over mDNS before CASE can start.
- **A persistent store** of the fabric and of the commissioned nodes, so that a node is reachable after a restart. `Commissioner.Connect()` reconnects to it with a fresh CASE handshake.
- **The Interaction Model**: Read, Write and Invoke, including the reassembly of a chunked list, over the Message Reliability Protocol.
- **Clusters**, as a client: Basic Information, Descriptor, General Commissioning, General Diagnostics, Network Commissioning, Operational Credentials, Access Control and On/Off.
- **Encoding**: TLV, the Matter message frame format, Base38, the manual pairing code and the QR code payload.
- **`matterctl`**, which scans, commissions and then reads, writes and invokes the clusters of a node from a terminal.

### Known limitations

- The device attestation chain of trust is **not validated**: the exchange runs and its response is parsed, but the certificate chain is accepted without being verified against the Distributed Compliance Ledger.
- There are no Interaction Model subscriptions: an attribute is read on demand.
- Thread commissioning, groups, bindings, scenes, OTA software update and CASE session resumption are not implemented.
- The On/Off cluster and the credentials handling have not been exercised against a wide range of real devices.
