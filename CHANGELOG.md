# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A pluggable storage backend** for the persistent store. `store.KVStore` holds byte values under slash-separated keys and `store.TxKVStore` adds atomic multi-key transactions, which a device will need for the fail-safe. `store.FileKVStore` (one file per key, written atomically, transactions journaled) and `store.MemKVStore` are provided, and `store.NewStoreWithKVStore` builds the typed `Store` on any backend.
- `matter.WithCommissionerStore` passes a `Store` to a `Commissioner` instead of the file store under `~/.{app-name}/`.
- `store.NewMemStore`, an in-memory `Store` for tests, and `Store.DeleteCommissionee`, which forgets a device.

### Changed

- `Store` no longer has a `Dir()` method, since a store which is not backed by a directory has none. `store.FileKVStore.Dir()` still returns it.
- A record is written to a temporary file and renamed into place, so a crash can no longer leave a truncated JSON file. The directory layout is unchanged, and an existing `~/.{app-name}/` directory is read as it is.

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
