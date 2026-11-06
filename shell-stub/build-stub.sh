#!/usr/bin/env bash

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$SDK" && -f "$ROOT/local.properties" ]]; then
  SDK="$(grep -E '^sdk.dir=' "$ROOT/local.properties" | cut -d= -f2-)"
fi
[[ -n "$SDK" ]] || { echo "Set ANDROID_HOME or sdk.dir in local.properties"; exit 1; }

BT_VER="$(grep -E '^rscoders.buildToolsVersion=' "$ROOT/local.properties" 2>/dev/null | cut -d= -f2- || true)"
[[ -n "${BT_VER:-}" ]] || BT_VER="$(ls "$SDK/build-tools" | sort -V | tail -1)"
BT="$SDK/build-tools/$BT_VER"

PLATFORM_JAR="$(ls -d "$SDK"/platforms/android-*/android.jar | sort -V | tail -1)"
[[ -f "$PLATFORM_JAR" ]] || { echo "no android.jar under $SDK/platforms"; exit 1; }

OUT="$HERE/build"
CLASSES="$OUT/classes"
rm -rf "$OUT"; mkdir -p "$CLASSES"

echo ">> javac (against $(basename "$(dirname "$PLATFORM_JAR")"))"
javac -source 8 -target 8 -bootclasspath "$PLATFORM_JAR" \
  -d "$CLASSES" \
  $(find "$HERE/src" -name '*.java')

echo ">> d8 -> classes.dex"
"$BT/d8" --min-api 21 --lib "$PLATFORM_JAR" --output "$OUT" \
  $(find "$CLASSES" -name '*.class')

echo "   -> $OUT/classes.dex"
