#!/bin/sh
# Offline tests only: do not replace with the network/BLE integration make test.
set -eu
export GOWORK=off
export GOPROXY=off
export GOSUMDB=off

test -z "$(gofmt -l cmd/matterctl matter/commissioner_impl.go matter/commissioner_impl_test.go)"
go vet ./cmd/matterctl/... ./matter ./matter/cmd ./matter/store ./matter/encoding/... ./matter/protocol/im ./matter/protocol/pase ./matter/protocol/case
golangci-lint run ./cmd/matterctl/... ./matter --timeout=5m
go test -p 1 -race -count=1 ./cmd/matterctl/... ./matter/cmd ./matter/store ./matter/encoding/... ./matter/protocol/im ./matter/protocol/pase ./matter/protocol/case
go test -race -count=1 ./matter -run 'Test(CommissionMatching|CommissionNoMatch|CommissionDiscovery|Connect|StartUsesInjected)'
# Cross-build in a temporary directory. No binary or credential enters the repo.
task_build_dir=$(mktemp -d)
trap 'rm -rf "$task_build_dir"' EXIT HUP INT TERM
if [ "$(go env GOOS)" = darwin ]; then
  # The existing BLE dependency requires Apple CoreBluetooth and CGO.
  GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -o "$task_build_dir/matterctl-darwin-arm64" ./cmd/matterctl
fi
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$task_build_dir/matterctl-linux-arm64" ./cmd/matterctl
# Help is routed before commissioner startup; no socket is opened.
go run ./cmd/matterctl tui --help >/dev/null
# A library consumer must not acquire terminal UI dependencies.
if go list -deps ./matter | rg 'github.com/(rivo/tview|gdamore/tcell)'; then
  echo 'unexpected UI dependency in matter library' >&2
  exit 1
fi
