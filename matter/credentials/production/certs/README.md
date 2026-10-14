# Production trust anchors of the Distributed Compliance Ledger

The files in this directory are public certificates of the Connectivity
Standards Alliance's Distributed Compliance Ledger (DCL), as mirrored in the
Matter SDK, [project-chip/connectedhomeip](https://github.com/project-chip/connectedhomeip),
at commit `61485549cbf9b80a894f256bcb0e15060677dba9` (2026-10-13). The SDK
is licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE).

| File | Source in connectedhomeip |
|------|---------------------------|
| `cd/CSA_Matter_CD_Signing_Key_00N.der` (N = 1 to 5) | `credentials/production/cd-certs/dcld_mirror_CN_Certification_Declaration_Signing_Key_00N_O_CSA_vid_0xC5A0_1.der` |

They are the certificates of the keys with which the Alliance signs the
Certification Declarations of certified products. A commissioner trusts
them in every attestation mode but `none`.
