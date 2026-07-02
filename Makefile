# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: MIT
#
# CI invokes these targets, never the underlying tooling directly, so local and
# CI commands stay in sync. `make verify` is the fast host-native inner loop;
# `make verify-ci` reproduces the FULL CI gate locally (Linux clippy + the
# code-quality checks) before pushing — see lint-linux/typos below for the two
# gaps that used to pass locally and fail in CI.

CARGO ?= cargo

# Docker image for lint-linux. CI runs clippy on Linux, so cfg(target_os =
# "linux") code is compiled and linted there but skipped by host clippy on a
# macOS/Windows dev box. The official rust image tracks stable like CI does;
# bookworm matches CI's Debian/Ubuntu-family glibc.
LINUX_RUST_IMAGE ?= rust:1-bookworm

# Pin the quality tools to the versions CI uses. Keep in lockstep with
# .github/workflows/code-quality.yml (both install these exact versions).
TYPOS_VERSION ?= 1.47.2

.PHONY: all build verify verify-ci fmt fmt-check lint lint-linux \
        typos machete deny coverage test test-netbox clean

all: build

build:
	$(CARGO) build --workspace

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all --check

lint:
	$(CARGO) clippy --workspace --all-targets -- -D warnings

# Reproduce CI's Linux clippy on a non-Linux host: run it in a Linux container so
# cfg(target_os = "linux") code is compiled and linted (host clippy on macOS
# skips it) — the gap CI kept catching. Native Linux in the container, so no
# cross-toolchain. protoc is a hard build dep (osa-proto, AD-6), installed like
# CI. A named volume caches the crate registry; a separate target dir avoids
# clobbering host (macOS) build artifacts. Needs Docker.
lint-linux:
	docker run --rm \
		-v "$(CURDIR)":/src -w /src \
		-v osa-lint-linux-registry:/usr/local/cargo/registry \
		-e CARGO_TARGET_DIR=/src/target/linux-ci \
		$(LINUX_RUST_IMAGE) \
		bash -eu -c 'apt-get update -qq && apt-get install -y -qq protobuf-compiler >/dev/null && rustup component add clippy >/dev/null 2>&1; cargo clippy --workspace --all-targets -- -D warnings'

# Spelling, pinned to CI's version so a drift can't flag different words in one
# place and not the other (the 4.3a failure mode).
typos:
	@have=$$(typos --version 2>/dev/null | awk '{print $$NF}'); \
	if [ "$$have" != "$(TYPOS_VERSION)" ]; then \
		echo "typos $$have installed, CI pins $(TYPOS_VERSION); install it:"; \
		echo "  cargo install typos-cli --version $(TYPOS_VERSION) --locked"; \
		exit 1; \
	fi; \
	typos

# Dependencies declared but never used.
machete:
	$(CARGO) machete

# Security advisories, licenses, banned crates, untrusted sources.
deny:
	$(CARGO) deny check

# Coverage summary (informational; no threshold yet). Needs llvm-tools-preview.
coverage:
	$(CARGO) llvm-cov --workspace --summary-only

test:
	$(CARGO) test --workspace

# Real-NetBox integration test (5.2a.2): boots NetBox + Postgres + Redis (~2-3 min
# per run). #[ignore]d out of the normal gate; run here and in the dedicated
# netbox-integration CI job, not the fast inner loop. Needs Docker.
test-netbox:
	$(CARGO) test -p osa-coordinator --bin osa-coordinator -- --ignored real_netbox

# Fast inner loop (host-native): format, clippy, test.
verify: fmt-check lint test

# Full CI parity (slower; lint-linux needs Docker). Run before pushing.
verify-ci: verify lint-linux typos machete deny

clean:
	$(CARGO) clean
