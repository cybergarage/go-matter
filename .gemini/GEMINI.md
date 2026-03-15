# Gemini Context: go-matter

## Specification & Reference

`go-matter` implements Matter Specification Version 1.5. Code comments cite relevant spec sections (e.g., `// 2.5.2. Vendor Identifier`). The implementation is based on the official C++ reference: https://github.com/project-chip/connectedhomeip.

## Project Overview

- **Core Library:** Located in the `matter/` directory, providing interfaces for Commissioners, Commissionees, and Devices.
- **CLI Tool:** `matterctl` (in `cmd/matterctl/`) for scanning and pairing Matter devices.
- **Transports:** Supports BLE (Bluetooth Low Energy) and mDNS (Multicast DNS) for device discovery.
- **Encoding:** Implements Matter-specific encodings including TLV (Tag-Length-Value), Base38, and Message Frame formats.
- **Security:** Includes implementations for PASE (Passcode-Authenticated Session Establishment) and PAKE (Password-Authenticated Key Exchange).

## Key Technologies

- **Language:** Go
- **CLI Framework:** [Cobra](https://github.com/spf13/cobra) and [Viper](https://github.com/spf13/viper)
- **Logging:** `github.com/cybergarage/go-logger`
- **External Dependencies:**
  - `github.com/cybergarage/go-ble`: BLE communication.
  - `github.com/cybergarage/go-mdns`: mDNS service discovery.

## Architecture

The project follows a modular structure:
- `matter/`: Core interfaces and common types.
- `matter/ble/`: BLE transport protocol and scanning.
- `matter/mdns/`: mDNS service discovery.
- `matter/encoding/`: Data encoding and decoding (TLV, Base38, QR, Message).
- `matter/crypto/`: Cryptographic primitives.
- `matter/protocol/`: Higher-level protocols (MRP, PASE).
- `mattertest/`: Comprehensive test suites and helpers.

## Building and Running

The project uses a `Makefile` for common tasks.

### Build and Install
- **Install `matterctl` CLI:**
  ```bash
  make install
  ```
  Or directly via Go:
  ```bash
  go install ./cmd/matterctl
  ```

### Development Commands
- **Format Code:** `make format` (runs `gofmt`)
- **Lint:** `make lint` (runs `golangci-lint`)
- **Vet:** `make vet` (runs `go vet`)
- **Test:** `make test` (runs tests with coverage)
- **Clean:** `make clean`

### Versioning
The version is managed via `matter/version.gen`, which generates `matter/version.go`. Running `make version` or `make format` will update this file.

## Usage: `matterctl`

`matterctl` provides several commands for interacting with Matter devices:
- `matterctl scan`: Scans for commissionable Matter devices via mDNS and BLE.
- `matterctl pairing code <nodeID> <pairingCode>`: Pairs a device using a manual pairing code.
- `matterctl doc`: Generates markdown documentation for the CLI tool.

## Development Conventions

- **License:** All source files must include the Apache 2.0 license header.
- **Testing:** Tests are located in both the package directories and the `mattertest/` directory. New features should be accompanied by tests in `mattertest/`.
- **Formatting:** Use `make format` before committing to ensure consistent code style.
- **Documentation:** Command-line documentation is partially automated via `matterctl doc`.
