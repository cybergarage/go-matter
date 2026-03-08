# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
# Full pipeline: format → vet → lint → test
make test

# Individual steps
make format   # runs version.gen then gofmt
make vet      # go vet
make lint     # golangci-lint
make install  # build+install matterctl CLI and regenerate doc/matterctl.md

# Run a single test
go test -v -run TestName ./matter/...
go test -v -run TestName ./mattertest/...

# Run all tests without linting
go test -v -p 1 -timeout 10m -cover -coverpkg=github.com/cybergarage/go-matter/matter/... \
  -coverprofile=matter-cover.out \
  github.com/cybergarage/go-matter/matter/... \
  github.com/cybergarage/go-matter/mattertest/...
```

Tests run with `-p 1` (single-threaded) because BLE and mDNS operations are not concurrency-safe across test cases.

## Architecture

`go-matter` is a Go library implementing the [Matter](https://buildwithmatter.com/) smart home/IoT protocol. Module root: `github.com/cybergarage/go-matter`.

### Package Layout

| Package | Role |
|---|---|
| `matter/` | Core public interfaces and type aliases — single import point for library users |
| `matter/types/` | Fundamental Matter types: VendorID, ProductID, Discriminator, Passcode, … |
| `matter/encoding/` | `base38`, `tlv`, `message` (frame format), `qr`, `pairing` |
| `matter/ble/` | BLE transport — BTP (Bluetooth Transport Protocol), Central/scanner |
| `matter/mdns/` | mDNS discovery of commissionable devices |
| `matter/protocol/mrp/` | Message Reliability Protocol (acknowledgement, counters) |
| `matter/protocol/pase/` | PASE commissioning handshake (SPAKE2+) |
| `matter/protocol/pase/pbkdf/` | PBKDF parameter negotiation messages |
| `matter/protocol/pase/pake/` | PAKE1/2/3 message types for SPAKE2+ |
| `matter/crypto/` | Elliptic curve, SPAKE2+, PBKDF, signature primitives |
| `matter/errors/` | Shared error definitions |
| `matter/io/` | Transport interface abstraction |
| `mattertest/` | Integration tests (separate Go package, exercises public `matter` API) |
| `cmd/matterctl/` | CLI tool built with Cobra + Viper |

### Key Design Patterns

- **Interfaces in `*.go`, implementations in `*_impl.go`** — e.g., `commissioner.go` defines the interface; `commissioner_impl.go` has the struct.
- The root `matter/` package re-exports types from sub-packages as type aliases so users have a single import path.
- `Commissioner` embeds `ble.Central` and `mdns.Discoverer`, supporting simultaneous BLE (BTP) and mDNS discovery.
- `Device` / `CommissionableDevice` / `Node` form the core domain model.
- Integration tests live in `mattertest/`; unit tests sit alongside source files inside each sub-package.

### Dependencies

Depends on sibling `cybergarage` packages (`go-ble`, `go-mdns`, `go-logger`) developed in parallel — these may have unreleased APIs.

## Conventions

- **Spec references in comments**: cite the Matter spec section in comments (e.g., `// 2.5.2. Vendor Identifier`, `// 5.4.3. Discovery by Commissioner`). Follow this pattern for new code.
- **`version.go` is generated**: `make format` runs `matter/version.gen` to regenerate `matter/version.go`. Do not edit it manually.
- **Linter**: golangci-lint v2, configured in `.golangci.yaml`. Run `make lint` before submitting changes.
- **Test logging**: use `go-logger` (`log.EnableStdoutDebug(true)`) for debug output in tests, not `t.Log`.
