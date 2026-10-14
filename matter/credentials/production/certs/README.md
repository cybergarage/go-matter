# Production trust anchors of the Distributed Compliance Ledger

The files in this directory are public certificates of the Connectivity
Standards Alliance's Distributed Compliance Ledger (DCL), named by their
subject key ID:

| Directory | Content |
|-----------|---------|
| `paa/` | The approved Product Attestation Authorities (PAAs): the DCL's approved root certificates, without the Matter Certification and Testing CA |
| `cd/` | The Certification Declaration signing certificates: the certificates the Matter Certification and Testing CA issued |

The current snapshot was taken from the DCL mirror of the Matter SDK,
[project-chip/connectedhomeip](https://github.com/project-chip/connectedhomeip),
`credentials/production/paa-root-certs` and `credentials/production/cd-certs`,
at commit `61485549cbf9b80a894f256bcb0e15060677dba9` (2026-10-13). The SDK
is licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE).

## Refreshing the snapshot

```
make update-production-certs
```

reads both sets from the production DCL's REST API
(`https://on.dcl.csa-iot.org`) with `matter/credentials/dcl`, and replaces the
`.der` files here. The `dcl-certs` workflow runs it monthly and opens a pull
request when the ledger changed. A directory of certificates can be used
instead of the ledger:

```
go run ./matter/credentials/production/internal/update -paa-dir DIR -cd-dir DIR
```
