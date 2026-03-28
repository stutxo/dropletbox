#!/usr/bin/env bash
set -euo pipefail

PKG_NAME=dropletbox
PKG_DIR=pkg

LLVM_PREFIX=$(brew --prefix llvm)
export PATH="$HOME/.cargo/bin:$LLVM_PREFIX/bin:$PATH"
export CC_wasm32_unknown_unknown="$LLVM_PREFIX/bin/clang"
export AR_wasm32_unknown_unknown="$LLVM_PREFIX/bin/llvm-ar"
export CFLAGS_wasm32_unknown_unknown="--target=wasm32-unknown-unknown"

echo "Using wasm-pack at: $(command -v wasm-pack)"
wasm-pack --version

echo "Building release package with wasm-pack..."
rm -rf "$PKG_DIR"

wasm-pack build \
  --release \
  --target web \
  --out-dir "$PKG_DIR" \
  --out-name "$PKG_NAME"

rm -f "$PKG_DIR/.gitignore" "$PKG_DIR/README.md"

ls -lh "$PKG_DIR/${PKG_NAME}_bg.wasm" "$PKG_DIR/${PKG_NAME}.js"
