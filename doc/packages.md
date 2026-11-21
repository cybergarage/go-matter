# Packages

The packages of go-matter, and which of them follow semantic versioning from v1.0.0. Paths are relative to `github.com/cybergarage/go-matter/matter`, except `cmd/matterctl`.

## API stability

From v1.0.0, the API of these packages follows [semantic versioning](https://semver.org/spec/v2.0.0.html), and changes incompatibly only in a new major version:

| Package | What is stable |
|---------|----------------|
| `matter` | The commissioner, the node and their options |
| `config`, `types`, `errors` | Configurations, identifiers and errors |
| `encoding`, `encoding/tlv` | Onboarding payloads and codes; TLV |
| `store`, `keystore` | The fabric and node records; the keys of the fabric |
| `credentials`, `credentials/testcreds` | Attestation, certificates and test credentials |
| `cluster/...` | The cluster clients |
| `datamodel`, `datamodel/command` | The data model catalog and command encoding |
| `protocol/im` | As a client uses it: paths and identifiers, reads, writes and invokes, subscriptions, events, `WithContext` |
| `ble`, `mdns` | As they are given to the commissioner |

The other packages, such as `protocol/case`, `protocol/pase`, `protocol/mrp`, `protocol/session`, `protocol/group`, `encoding/message`, `ble/btp` and `crypto`, are the parts the commissioner is built of: they are public so that they can be tested and reused, and they may change in a minor version. `device` and `device/cluster`, the device side, are experimental until v1.1.0.

## Packages

| Category | Package | Status | Description |
|----------|---------|--------|-------------|
| Discovery | `ble/btp` | ✅ Implemented | BLE transport protocol (BTP) implementation |
|           | `mdns` | ✅ Implemented | mDNS (Multicast DNS) service discovery |
| Commissioning | `protocol/pase` | ✅ Implemented | Passcode-Authenticated Session Establishment (PASE / SPAKE2+) |
|               | `protocol/case` | ✅ Implemented | Certificate-Authenticated Session Establishment (CASE), with session resumption (Sigma2_Resume) |
|               | `protocol/session` | ✅ Implemented | Secure session management |
|               | `credentials` | ✅ Implemented | Device attestation verification (DAC → PAI → PAA, Certification Declaration), CSR, and CA/NOC chain handling |
|               | `credentials/production` | ✅ Implemented | Bundled snapshot of the DCL's production PAAs and CD signing certificates |
|               | `credentials/dcl` | ✅ Implemented | DCL REST client which refreshes that snapshot (`make update-production-certs`) |
|               | `store` | ✅ Implemented | Persistent fabric and commissionee record store |
|               | `keystore` | ✅ Implemented | Key store for the fabric's private keys: encrypted files, or any `crypto.Signer` (HSM, KMS, TPM) |
| Interaction Model | `protocol/im` | ✅ Implemented | Read/Write/Invoke transactions, incl. chunked list reassembly; attribute and event subscriptions; event reads; exchange multiplexing (`ExchangeMux`) |
|                    | `protocol/mrp` | ✅ Implemented | Message Reliability Protocol (acknowledgement, counters) |
| Clusters | `cluster` | ✅ Implemented | Basic Information, Descriptor, General Commissioning/Diagnostics, Network Commissioning, Operational Credentials, Access Control, Administrator Commissioning |
|          | `cluster/administratorcommissioning` | ✅ Implemented | Multi-admin: open a commissioning window on a commissioned node with a fresh passcode (`NewWindow`, `OpenCommissioningWindow`), with its manual pairing code and QR code; basic windows and revocation |
|          | `cluster/onoff` | ✅ Implemented | On/Off cluster client |
| Operation | `cmd/matterctl` | ✅ Implemented | `matterctl` CLI (scan, pairing, per-cluster read/write/invoke, subscriptions, events) and the `matterctl tui` full-screen controller |
| Encoding | `encoding/base38` | ✅ Implemented | Base38 encoding/decoding |
|          | `encoding/qr` | ✅ Implemented | QR code generation |
|          | `encoding/pairing` | ✅ Implemented | Manual pairing code handling |
|          | `encoding/message` | ✅ Implemented | Message Frame Format encoding |
|          | `encoding/tlv` | ✅ Implemented | TLV (Tag-Length-Value) encoding |
