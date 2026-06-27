# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: MIT
#
# CI invokes these targets, never the underlying tooling directly, so local and
# CI commands stay in sync.

CARGO ?= cargo

.PHONY: all build verify fmt fmt-check lint test clean

all: build

build:
	$(CARGO) build --workspace

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

lint:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

test:
	$(CARGO) test --workspace

verify: fmt-check lint test

clean:
	$(CARGO) clean
