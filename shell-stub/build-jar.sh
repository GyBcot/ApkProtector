set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [[ -z "$SDK" && -f "$ROOT/local.properties" ]]; then
  SDK="$(grep -E '^sdk.dir=' "$ROOT/local.properties" | cut -d= -f2-)"
fi
PLAT="$(ls -d "$SDK"/platforms/android-*/android.jar | sort -V | tail -1)"

OUT="$HERE/build"; rm -rf "$OUT/jar-classes"; mkdir -p "$OUT/jar-classes"
echo ">> javac"
javac -source 8 -target 8 -bootclasspath "$PLAT" -d "$OUT/jar-classes" \
  $(find "$HERE/src" -name '*.java') 2>/dev/null
echo ">> jar"
(cd "$OUT/jar-classes" && jar cf "$OUT/rscoders-runtime.jar" com)
echo "   -> $OUT/rscoders-runtime.jar"
