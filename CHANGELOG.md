# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A pluggable storage backend** for the persistent store. `store.KVStore` holds byte values under slash-separated keys and `store.TxKVStore` adds atomic multi-key transactions, which a device will need for the fail-safe. `store.FileKVStore` (one file per key, written atomically, transactions journaled) and `store.MemKVStore` are provided, and `store.NewStoreWithKVStore` builds the typed `Store` on any backend.
- `matter.WithCommissionerStore` passes a `Store` to a `Commissioner` instead of the file store under `~/.{app-name}/`.
- `store.NewMemStore`, an in-memory `Store` for tests, and `Store.DeleteCommissionee`, which forgets a device.
- **A device-side store**, the groundwork for running as a Matter device. `store.DeviceStore` keeps the fabrics a device has joined with their operational credentials, the Access Control entries and the group keys of each fabric, and removes all three together as RemoveFabric does. Its transactions let the changes made while a fail-safe is armed be committed or rolled back as one.
- **The PASE responder**, `pase.Responder`, the device side of PASE. It authenticates a commissioner against a `pase.Verifier` (w0, L, salt and iterations) rather than the passcode itself.
- **`matter/device`**, the start of the device role: a `Device` listens on UDP, answers PASE with its verifier, and hands each new session to the application. `CommissionableService` describes its `_matterc._udp` service (instance name, subtypes and TXT entries), which the default `MDNSAdvertiser` publishes with the go-mdns responder.
- **An Interaction Model server**, `im.Server`, which answers Invoke and Read (with wildcard paths) with registered command handlers and attribute readers. A report must fit in one message.
- `session.WithRole(session.RoleResponder)`, so a device can use a secure session with the responder's keys and session IDs.
- The device serves the Interaction Model on each PASE session with the **General Commissioning cluster**: ArmFailSafe, SetRegulatoryConfig, CommissioningComplete (over CASE only) and its attributes. The fail-safe guards the commissioning changes with a `DeviceStore` transaction, rolled back when it expires. `device.WithDeviceStore` sets the store.
- `credentials.AttestationProvider` and `credentials.Signer`, which a device proves its origin and signs with without exposing its private keys, with `NewAttestationProvider`, `NewSoftwareSigner`, `CreateCSR`, `BuildAttestationElements`, `BuildNOCSRElements` and `SignWithChallenge` for the device side of attestation and CSR.
- `credentials/testcreds`: the public test attestation credentials of the Matter SDK (project-chip/connectedhomeip, Apache License 2.0) for vendor 0xFFF1 and product 0x8000, for development and testing only. The source is given in the README, `NOTICE` and `matter/credentials/testcreds/certs/README.md`.
- The device serves the **Operational Credentials cluster**: AttestationRequest and CertificateChainRequest with the credentials `device.WithAttestationProvider` sets, CSRRequest with a newly generated operational key, AddTrustedRootCertificate, and AddNOC, which checks the NOC and writes the fabric, an Administer ACL entry for CaseAdminSubject and the IPK through the fail-safe's transaction. The NOCs, Fabrics, SupportedFabrics, CommissionedFabrics and TrustedRootCertificates attributes report the fabrics, the one being added included. `device.WithSupportedFabrics` sets how many fabrics the device can join.
- `credentials.ParseOperationalCertificate`, `VerifyRootCertificate` and `VerifyOperationalChain`, which read Matter TLV operational certificates and check a NOC chains to its root.
- **The CASE responder**, `caseprotocol.Responder`, the device side of CASE. It finds the fabric a Sigma1's destination ID names among the device's fabrics, proves the device's identity on it in Sigma2, and checks in Sigma3 that the initiator's NOC chains to that fabric's root. Session resumption is not supported; a resumption request gets a full Sigma2.
- The device answers **CASE** on the fabrics it has joined, the one being added under the fail-safe included, and serves the Interaction Model on CASE sessions, so commissioning completes: CommissioningComplete over CASE on the new fabric commits it. AddNOC binds the PASE session to the new fabric, and rolling the fail-safe back closes the CASE sessions on it. `Session.IsCASE` and `Session.PeerNodeID` describe a session.
- The device advertises an **operational service** (`_matter._tcp`, `<compressed fabric ID>-<node ID>` with the `_I` subtype) for each fabric it is on, from AddNOC on, so a commissioner finds it for CASE; rolling the fail-safe back withdraws it. `device.OperationalService` describes it.
- **The commissioning window.** A device advertises itself as commissionable and accepts PASE only while its window is open: at Start when it is on no fabric (`device.WithCommissioningTimeout`, 15 minutes by default), or after `OpenCommissioningWindow`. A PASE session takes the window: the device stops advertising, arms the fail-safe for 60 seconds and refuses other commissioners. A failed attempt, PASE failing or the fail-safe expiring, advertises again, and the window closes after 20 of them, when it times out, on `CloseCommissioningWindow`, or when CommissioningComplete succeeds, which also ends the PASE sessions.
- `pase.WithResponderEstablishedHandler` and `caseprotocol.WithResponderEstablishedHandler`, which hand the new session over before the initiator is told it is established, so the device has set it up by the time the initiator's first message arrives.
- `mattertest` commissions a `matter/device` Device with go-matter's own Commissioner over real mDNS and UDP, from discovery to CommissioningComplete.
- `mattertest` commissions a `matter/device` Device with **chip-tool** when it is installed (`$CHIP_TOOL` or `chip-tool` on the PATH, such as the chip-tool snap), and reads an attribute over CASE afterwards, logging chip-tool's output. `make test-chip-tool` runs only these tests, and `GO_MATTER_TEST_REQUIRE=chip-tool` fails them instead of skipping when chip-tool is missing. A GitHub Actions job installs Avahi and the chip-tool snap to run them.
- `TestChipToolOpensCommissioningWindow` has chip-tool open an enhanced commissioning window on the commissioned device, and a second chip-tool commissioner join a second fabric through it with the one-time passcode.
- `credentials.OperationalCertificate.CATs`, the CASE Authenticated Tags of a NOC.
- **Access control in `im.Server`.** `SetAccessChecker` subjects every invoke and read to a check with the privilege its handler requires (`im.WithPrivilege`; Operate for commands and View for attributes by default). A refused command or concrete read is answered with UNSUPPORTED_ACCESS, and a wildcard read leaves the attribute out. `HandleAttributeRead` registers a reader which gets the session and whether the read is fabric-filtered, for fabric-scoped attributes.
- The device enforces its **Access Control List**: a CASE request is granted when an entry of the session's fabric names its subject (node ID, or a CAT of at least the entry's version), the endpoint and cluster, and a privilege which grants the one required; a PASE session, which only exists while the commissioning window is open, is granted Administer. The General and Operational Credentials commands, and reading the NOCs, need Administer. CurrentFabricIndex reports the session's fabric, a fabric-filtered read of NOCs and Fabrics reports only it, and the certificates of other fabrics are left out of NOCs.
- `im.TimedInvoke`, which invokes a command in a timed interaction, as the commands which require one must be.
- `pase.Verifier.Bytes` and `pase.ParseVerifier`, the serialized verifier (w0 followed by L) the Administrator Commissioning cluster carries.
- The device serves the **Administrator Commissioning cluster**: OpenCommissioningWindow opens an enhanced window with the verifier and discriminator an administrator generated, advertised with CM=2, OpenBasicCommissioningWindow one with the device's own passcode, and RevokeCommissioning closes the window and ends a commissioning in progress; the WindowStatus, AdminFabricIndex and AdminVendorId attributes report the window. The commands need Administer and a timed interaction. `Device.OpenEnhancedCommissioningWindow` opens an enhanced window from the application.
- `pake.Pake1.PA`, `pake.Pake3.CA` and `pake.WithPake2MessagePrecomputed`, which the responder needs.
- `store.PersistentCounter`, a counter that never repeats a value across restarts without persisting every increment, for the boot count and the global group message counters.

### Fixed

- `Commissioner.Discover`, and so `Commission`, failed on a host without Bluetooth even when mDNS found the device, since a failing BLE scan aborted the discovery. A method which fails is now logged and the other's devices are returned; Discover fails only when both do. This also made `TestMockCommissioning`, and the GitHub Actions build job, fail wherever BlueZ is not running.
- Operational discovery never found a node: `mdns.NewOperationalNodeQuery` for a service instance asked for its PTR records, which an instance does not have, since go-mdns sends the query's own type instead of ANY. It now asks for ANY, and `mdns.Query` carries the question type (`WithQueryType`).
- `pbkdf.NewParamResponse` did not echo the initiator's random when the PBKDF parameters were given, so a responder with its own salt could not answer.
- A PASE initiator that fails to verify cB now sends a failure StatusReport, so the responder ends the exchange instead of waiting for Pake3 until its deadline.

### Changed

- A standalone MRP ack sets the initiator flag exactly when the acknowledged message did not, instead of always; a commissioner's acks are unchanged.
- `device.Session` no longer has `Transport()`: the device serves the Interaction Model on it.
- `device.Session.Keys` returns `session.SessionKeys`, since a session may now be a CASE one.
- `device.Advertiser` has `AdvertiseOperational`, which publishes the operational services, and `WithdrawCommissionable`, which withdraws the commissionable service when the commissioning window closes.
- A device already on a fabric no longer advertises itself as commissionable at Start, and a commissioned device no longer accepts PASE until its commissioning window is opened again.
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
