#!/usr/bin/env bash
# bimo-pc-agent — reproducible Windows build (gate step 1)
# Builds a real Windows x86_64 .exe from a clean state on this VM.
# Requirements: Rust 1.100.0+ (via rustup, ~/.cargo/bin), mingw-w64 linker
#   (apt: gcc-mingw-w64-x86-64), target x86_64-pc-windows-gnu installed.
# Usage: ./build-windows.sh [--clean] [--debug]
# Output: target/x86_64-pc-windows-gnu/release/bimo-agent.exe
# Exit codes: 0 = PE32+ exe produced and verified; 1 = build/link failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/bimo-pc-agent" && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"

CLEAN=0
PROFILE=release
for arg in "$@"; do
  case "$arg" in
    --clean) CLEAN=1 ;;
    --debug) PROFILE=debug ;;
  esac
done

echo "[build] rustc: $(rustc --version)"
echo "[build] linker: $(x86_64-w64-mingw32-gcc --version | head -1)"
echo "[build] target dir: $ROOT/target"

if [ "$CLEAN" = 1 ]; then
  echo "[build] clean build — wiping target/"
  rm -rf "$ROOT/target"
fi

cd "$ROOT"
cargo build --profile "$PROFILE" --target x86_64-pc-windows-gnu --locked

EXE="$ROOT/target/x86_64-pc-windows-gnu/$PROFILE/bimo-agent.exe"
if [ ! -f "$EXE" ]; then
  echo "[build] FAIL: no exe at $EXE" >&2
  exit 1
fi

echo "[build] verifying PE format:"
file "$EXE"
file "$EXE" | grep -q "PE32+ executable" || { echo "[build] FAIL: not a PE32+ exe" >&2; exit 1; }
echo "[build] size: $(stat -c%s "$EXE") bytes"
echo "[build] OK: $EXE"
