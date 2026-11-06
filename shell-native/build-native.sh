#!/usr/bin/env bash

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$SDK" && -f "$ROOT/local.properties" ]]; then
  SDK="$(grep -E '^sdk.dir=' "$ROOT/local.properties" | cut -d= -f2-)"
fi
[[ -n "$SDK" ]] || { echo "Set ANDROID_HOME or sdk.dir in local.properties"; exit 1; }

NDK_VER="$(grep -E '^rscoders.ndkVersion=' "$ROOT/local.properties" 2>/dev/null | cut -d= -f2- || true)"
if [[ -z "${NDK_VER:-}" ]]; then
  NDK_VER="$(ls "$SDK/ndk" | sort -V | tail -1)"
fi
NDK="$SDK/ndk/$NDK_VER"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
[[ -f "$TOOLCHAIN" ]] || { echo "NDK toolchain not found: $TOOLCHAIN"; exit 1; }

SDK_CMAKE_DIR="$(ls -d "$SDK"/cmake/*/bin 2>/dev/null | sort -V | tail -1 || true)"
if [[ -n "${SDK_CMAKE_DIR:-}" ]]; then
  export PATH="$SDK_CMAKE_DIR:$PATH"
  CMAKE="$SDK_CMAKE_DIR/cmake"
else
  CMAKE="cmake"
fi

ABIS=("arm64-v8a" "armeabi-v7a")
MIN_SDK=21
BUILD_TYPE="Release"

for ABI in "${ABIS[@]}"; do
  OUT="$HERE/build/$ABI"
  echo ">> building $ABI"
  "$CMAKE" -S "$HERE" -B "$OUT/.cmake" \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
    -DANDROID_ABI="$ABI" \
    -DANDROID_PLATFORM="android-$MIN_SDK" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -GNinja
  "$CMAKE" --build "$OUT/.cmake"
  cp "$OUT/.cmake/librscoders.so" "$OUT/librscoders.so"
  echo "   -> $OUT/librscoders.so"
done

echo "done."
