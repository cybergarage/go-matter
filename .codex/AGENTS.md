# Repository Guidelines

## Project Structure & Module Organization
- `matter/`: Core library packages (protocols, crypto, encoding, BLE, mDNS).
- `mattertest/`: Integration tests that exercise the public `matter` API.
- `cmd/matterctl/`: CLI tool built with Cobra/Viper.
- `doc/`: Generated CLI docs (e.g., `doc/matterctl.md`).
- `*.pcap*`: Packet captures used for debugging and reference.

## Build, Test, and Development Commands
- `make format`: Regenerates `matter/version.go` via `matter/version.gen` and runs `gofmt -s`.
- `make vet`: Runs `go vet` after formatting.
- `make lint`: Runs `golangci-lint` (config in `.golangci.yaml`).
- `make test`: Full pipeline `format → vet → lint → test` with coverage output.
- `make install`: Installs `matterctl` and regenerates `doc/matterctl.md`.
- `go test -v -run TestName ./matter/...`: Run a focused unit test.
- `go test -v -run TestName ./mattertest/...`: Run a focused integration test.

## Coding Style & Naming Conventions
- Follow standard Go formatting (`gofmt -s`); no manual alignment.
- Interfaces live in `*.go` with implementations in `*_impl.go` (e.g., `commissioner.go`/`commissioner_impl.go`).
- Add Matter spec section references in comments (e.g., `// 5.4.3. Discovery by Commissioner`).
- `matter/version.go` is generated; do not edit by hand.
- For test logging, use `go-logger` (e.g., `log.EnableStdoutDebug(true)`), not `t.Log`.

## Testing Guidelines
- Unit tests live alongside packages; integration tests live in `mattertest/`.
- Run tests single-threaded with `-p 1` because BLE and mDNS tests are not concurrency-safe.
- Coverage output is written to `matter-cover.out` and HTML to `matter-cover.html` during `make test`.

## Commit & Pull Request Guidelines
- Use Conventional Commits with scopes, matching history:
  - `feat(pase): add ...`, `fix(crypto): ...`, `refactor(crypto)!: ...`.
- Keep commits focused and update generated docs when CLI behavior changes (`make install`).
- PRs should include a brief summary, tests run, and any spec or doc updates needed.

## Security & Configuration Tips
- `make codecov` uses a local `CODECOV_TOKEN` file; keep tokens out of commit history.
