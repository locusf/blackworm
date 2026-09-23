#!/bin/bash
# Build Lean targets and their tracked OpenSSL FFI dependency.
set -euo pipefail

cd "$(dirname "$0")"

for tool in cc lake; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: $tool not found. Please install it first." >&2
        exit 1
    fi
done

args=()
if [[ -n "${OPENSSL_DIR:-}" ]]; then
    args+=("-KopensslPrefix=$OPENSSL_DIR")
elif [[ "$OSTYPE" == darwin* ]] && command -v brew >/dev/null 2>&1; then
    args+=("-KopensslPrefix=$(brew --prefix openssl@3)")
fi

lake "${args[@]}" build Blackworm Bench bench Test test
echo "Build complete. Run 'lake exe test' for correctness checks."
