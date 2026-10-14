# Test attestation credentials from the Matter SDK

The files in this directory are copied, unmodified, from the Matter SDK,
[project-chip/connectedhomeip](https://github.com/project-chip/connectedhomeip),
at commit `d305b0761957c960c26c0841e1b50add2365871d` (2026-09-28). They are
licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE) and
[NOTICE](NOTICE), copied from the same commit.

| File | Source in connectedhomeip |
|------|---------------------------|
| `Matter-Development-DAC-FFF1-8000-Cert.der` | `credentials/development/attestation/Matter-Development-DAC-FFF1-8000-Cert.der` |
| `Matter-Development-DAC-FFF1-8000-Key.der` | `credentials/development/attestation/Matter-Development-DAC-FFF1-8000-Key.der` |
| `Matter-Development-PAI-FFF1-noPID-Cert.der` | `credentials/development/attestation/Matter-Development-PAI-FFF1-noPID-Cert.der` |
| `Chip-Test-PAA-FFF1-Cert.der` | `credentials/development/paa-root-certs/Chip-Test-PAA-FFF1-Cert.der` |
| `Chip-Example-CD-FFF1.der` | `kCdForAllExamples` for VID 0xFFF1 in `src/credentials/examples/DeviceAttestationCredsExample.cpp`, written out as a file |
| `CSA_Matter_CD_Signing_Key_001.cert.der` | `credentials/development/cd-certs/CSA_Matter_CD_Signing_Key_001.cert.der` |
| `Chip-Test-CD-Cert.der` | `credentials/development/cd-certs/Chip-Test-CD-Cert.der`, at commit `61485549cbf9b80a894f256bcb0e15060677dba9` (2026-10-13) |

They are the credentials the SDK's example applications use: the DAC for
vendor ID 0xFFF1 and product ID 0x8000, the PAI which issued it, the test PAA
at the root of that chain, and the Certification Declaration which covers
vendor 0xFFF1 and products 0x8000 to 0x8063, signed with the CD signing key
whose certificate is included. That key, CSA Certification Declaration
Signing Key 001, is a production key of the Connectivity Standards Alliance;
the declaration is for development and test by its vendor ID and its
certification type. `Chip-Test-CD-Cert.der` is the SDK's test CD signing key,
"Matter Test CD Signing Authority", whose private key is public: a
commissioner trusts it in development mode only.

**They are for development and testing only.** The DAC's private key is
public, and the vendor ID 0xFFF1 is reserved for testing. Commissioners
accept these credentials only in development mode. A product needs its own
vendor ID, attestation credentials and certification from the Connectivity
Standards Alliance.
