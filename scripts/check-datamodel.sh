#!/bin/sh
# Metadata only. Never invoke network/BLE repository integration tests here.
set -eu
export GOWORK=off GOPROXY=off GOSUMDB=off
test -z "$(gofmt -l matter/datamodel)"
go vet ./matter/datamodel/...
golangci-lint run ./matter/datamodel/... --timeout=5m
go test -p 1 -race -count=1 ./matter/datamodel/...
task_build_dir=$(mktemp -d)
trap 'rm -rf "$task_build_dir"' EXIT HUP INT TERM
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$task_build_dir/generator-linux-arm64" ./matter/datamodel/internal/gen
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o "$task_build_dir/generator-darwin-arm64" ./matter/datamodel/internal/gen
