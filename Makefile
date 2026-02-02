# Copyright (C) 2022 The go-matter Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SHELL := bash

PATH := $(GOBIN):$(PATH)
GOBIN := $(shell go env GOPATH)/bin

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	OS_ENV = macOS
else ifeq ($(UNAME_S),Linux)
	OS_ENV = linux
else
	OS_ENV = other
endif

GOBIN := $(shell go env GOPATH)/bin
PATH := $(GOBIN):$(PATH)

MODULE_ROOT=github.com/cybergarage/go-matter

PKG_NAME=matter
PKG_VER=$(shell git describe --abbrev=0 --tags)
PKG_COVER=${PKG_NAME}-cover

PKG_ID=${MODULE_ROOT}/${PKG_NAME}
PKG_SRC_DIR=${PKG_NAME}
PKG=${MODULE_ROOT}/${PKG_SRC_DIR}

TEST_PKG_NAME=${PKG_NAME}test
TEST_PKG_ID=${MODULE_ROOT}/${TEST_PKG_NAME}
TEST_PKG_DIR=${TEST_PKG_NAME}
TEST_PKG=${MODULE_ROOT}/${TEST_PKG_DIR}

BIN_ROOT_DIR=cmd
BIN_ID=${MODULE_ROOT}/${BIN_ROOT_DIR}
BIN_CTL=matterctl
BIN_SRCS=\
	${BIN_ROOT_DIR}/${BIN_CTL}
BINS=\
	${BIN_ID}/${BIN_CTL}

DOCS_ROOT_DIR=doc

.PHONY: format vet lint clean
.IGNORE: lint

all: codecov

version:
	@pushd ${PKG_SRC_DIR} && ./version.gen > version.go && popd
	-git commit ${PKG_SRC_DIR}/version.go -m "Update version"

format: version
	gofmt -s -w ${PKG_SRC_DIR} ${TEST_PKG_DIR} ${BIN_ROOT_DIR}

vet: format
	go vet ${PKG_ID} ${TEST_PKG_ID} ${BINS}

lint: vet
	golangci-lint run ${PKG_SRC_DIR}/... ${TEST_PKG_DIR}/...

test: lint
	go clean -testcache
	go test -v -p 1 -timeout 10m -cover -coverpkg=${PKG}/... -coverprofile=${PKG_COVER}.out ${PKG}/... ${TEST_PKG}/...
	go tool cover -html=${PKG_COVER}.out -o ${PKG_COVER}.html

cover: test
	open ${PKG_COVER}.html || xdg-open ${PKG_COVER}.html || gnome-open ${PKG_COVER}.html

codecov: test
	@if [ ! -f ./codecov ]; then \
		if [ "$(OS_ENV)" = "macOS" ]; then \
			curl -Os https://cli.codecov.io/latest/macos/codecov && chmod +x codecov; \
		elif [ "$(OS_ENV)" = "linux" ]; then \
			curl -Os https://cli.codecov.io/latest/linux/codecov && chmod +x codecov; \
		fi \
	fi
	@if [ -f ./codecov ] && [ -f CODECOV_TOKEN ]; then \
		CODECOV_TOKEN=$$(cat CODECOV_TOKEN); \
		./codecov upload-process --disable-search -t $$CODECOV_TOKEN -f ${PKG_COVER}.out; \
	else \
		echo "codecov or CODECOV_TOKEN not found"; \
	fi

install:
	go install ${BINS}
	${GOBIN}/${BIN_CTL} doc > ${DOCS_ROOT_DIR}/${BIN_CTL}.md
	@git diff --quiet -- ${DOCS_ROOT_DIR}/${BIN_CTL}.md || \
		git commit ${DOCS_ROOT_DIR}/${BIN_CTL}.md -m "docs: update ${BIN_CTL} command reference"

clean:
	go clean -i ${PKG} ${TEST_PKG} ${BINS}
