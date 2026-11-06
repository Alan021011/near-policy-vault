#!/usr/bin/env bash
# Builds the three contracts the sandbox tests deploy and copies them to sandbox-tests/wasm/.
# Needs cargo-near (https://github.com/near/cargo-near). Same command as the deployed build:
# `cargo near build non-reproducible-wasm --no-abi`.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(dirname "$here")"
mkdir -p "$here/wasm"
for crate in contract:policy_vault mock-signer:mock_signer test-receiver:test_receiver; do
  dir="${crate%%:*}"; name="${crate##*:}"
  target="${CARGO_TARGET_BASE:-$repo/target}/$dir"
  (cd "$repo/$dir" && CARGO_TARGET_DIR="$target" cargo near build non-reproducible-wasm --no-abi)
  cp "$target/near/$name.wasm" "$here/wasm/$name.wasm"
done
sha256sum "$here"/wasm/*.wasm 2>/dev/null || shasum -a 256 "$here"/wasm/*.wasm
