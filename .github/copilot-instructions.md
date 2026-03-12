# Copilot Instructions for go-matter

## Specification & Reference

`go-matter` implements Matter Specification Version 1.5. Code comments cite relevant spec sections (e.g., `// 2.5.2. Vendor Identifier`). The implementation is based on the official C++ reference: https://github.com/project-chip/connectedhomeip.

## Build, Test, and Lint

```sh
# Format, vet, lint, then test with coverage
make test

# Steps individually
make format   # gofmt + version.go generation
make vet      # go vet
make lint     # golangci-lint
make install  # build and install matterctl CLI, regenerate doc/matterctl.md

# Run a single test
go test -v -run TestName ./matter/...
go test -v -run TestName ./mattertest/...

# Run all tests without linting
go test -v -p 1 -timeout 10m -cover -coverpkg=github.com/cybergarage/go-matter/matter/... \
  -coverprofile=matter-cover.out \
  github.com/cybergarage/go-matter/matter/... \
  github.com/cybergarage/go-matter/mattertest/...
```

The Makefile pipeline is: `format → vet → lint → test`. `make test` runs all steps.

## Architecture

`go-matter` is a Go library implementing the [Matter](https://buildwithmatter.com/) smart home protocol. The module root is `github.com/cybergarage/go-matter`.

### Package Layout

| Package | Role |
|---|---|
| `matter/` | Core public interfaces and type aliases (entry point for users) |
| `matter/ble/` | BLE transport — BTP (Bluetooth Transport Protocol), Central/scanner |
| `matter/mdns/` | mDNS discovery of commissionable devices |
| `matter/encoding/` | Encoding: `base38`, `tlv`, `message` (frame format), `qr`, `pairing` |
| `matter/protocol/mrp/` | Message Reliability Protocol (acknowledgement, session) |
| `matter/protocol/pase/` | PASE commissioning handshake (SPAKE2+) |
| `matter/crypto/` | Elliptic curve, SPAKE2+, PBKDF, signature primitives |
| `matter/types/` | Fundamental Matter types (VendorID, ProductID, Discriminator, …) |
| `matter/errors/` | Shared error definitions |
| `matter/io/` | Transport interface abstraction |
| `mattertest/` | Integration tests (a separate Go package; not in `matter/`) |
| `cmd/matterctl/` | CLI built with Cobra + Viper |

### Key Relationships

- **Interfaces live in `*.go`; concrete implementations live in `*_impl.go`** (e.g., `commissioner.go` defines the interface, `commissioner_impl.go` has the struct).
- The root `matter` package re-exports types from sub-packages as type aliases, giving users a single import point.
- `Commissioner` embeds `ble.Central` and `mdns.Discoverer`. Discovery covers both BLE (BTP) and mDNS transports simultaneously.
- `Device` / `CommissionableDevice` / `Node` form the core domain model.
- Integration tests in `mattertest/` import and exercise the public `matter` API; unit tests sit alongside their source files inside each sub-package.

### Dependencies

The library depends on sibling `cybergarage` packages (`go-ble`, `go-mdns`, `go-logger`) that are developed in parallel and may have unreleased APIs.

## Conventions

- **Spec references in comments**: code comments cite the Matter spec section (e.g., `// 2.5.2. Vendor Identifier`, `// 5.4.3. Discovery by Commissioner`). Follow this pattern when adding new code.
- **`*_impl.go` for implementations**: keep interface definitions and concrete structs in separate files.
- **`version.gen` script**: `make format` runs `version.gen` to regenerate `matter/version.go`. Do not edit `version.go` manually.
- **golangci-lint v2**: configuration is in `.golangci.yaml`. Many linters are enabled; the `issues.fix: true` setting auto-fixes what it can. Run `make lint` before submitting changes.
- **Test logging**: tests use `go-logger` (`log.EnableStdoutDebug(true)`) for debug output rather than `t.Log`.
- **`-p 1` serialisation**: tests run single-threaded (`-p 1`) because BLE and mDNS operations are not concurrency-safe across test cases.
