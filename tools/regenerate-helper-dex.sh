#!/usr/bin/env bash
# regenerate-helper-dex.sh — 重新编译并覆盖 17.17.0 的 android helper.dex
#
# 背景：de-frida.py 把 helper 的 Java 包名 re.frida -> re.gsvc，但检入的
#       helper.dex 仍是旧包名。17.17.0 的 meson 构建直接内嵌 src/android-helper/
#       helper.dex 文件（非 vala 字节数组），所以只需重新编译并覆盖该文件。
#
# 依赖：JDK（javac）、Android SDK（android.jar + d8）
# 用法：
#   export ANDROID_HOME=/path/to/android-sdk
#   bash tools/regenerate-helper-dex.sh
#
# 产物：subprojects/frida-core/src/android-helper/helper.dex（覆盖）
# 注意：仅 spawn 模式需要 helper；attach 模式不加载 helper，可跳过本步。

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HELPER_DIR="$ROOT/subprojects/frida-core/src/android-helper"
JAVA_SRC="$HELPER_DIR/re/gsvc/Helper.java"
JAVA_BACKEND="$HELPER_DIR/re/gsvc/HelperBackend.java"

# 1. 定位 android.jar
ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$ANDROID_HOME" ]; then
  echo "请先 export ANDROID_HOME=/path/to/android-sdk" >&2
  exit 1
fi
ANDROID_JAR="$(ls "$ANDROID_HOME"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1)"
if [ -z "$ANDROID_JAR" ]; then
  echo "找不到 android.jar（$ANDROID_HOME/platforms/android-*/android.jar）" >&2
  exit 1
fi
echo "[1/5] android.jar = $ANDROID_JAR"

# 2. 定位 d8（优先 PATH 里的，其次 build-tools）
D8="$(command -v d8 || true)"
if [ -z "$D8" ]; then
  D8="$(ls "$ANDROID_HOME"/build-tools/*/d8 2>/dev/null | sort -V | tail -1 || true)"
fi
if [ -z "$D8" ]; then
  echo "找不到 d8（请安装 Android build-tools）" >&2
  exit 1
fi
echo "[2/5] d8 = $D8"

# 3. javac 编译 re/gsvc/*.java
BUILD="$HELPER_DIR/build"
rm -rf "$BUILD"
mkdir -p "$BUILD/classes"
echo "[3/5] javac 编译 $JAVA_SRC + HelperBackend"
javac \
  -cp "$ANDROID_JAR" \
  -bootclasspath "$ANDROID_JAR" \
  -source 1.8 -target 1.8 \
  -Xlint:-deprecation -Xlint:-unchecked \
  -d "$BUILD/classes" \
  "$JAVA_SRC" "$JAVA_BACKEND"

# 4. 打 jar 后 d8 出 dex（--lib android.jar 做 desugaring，否则 HelperBackend
#    缺 java.util.Comparator 导致 server 崩溃 —— 历史踩坑）
echo "[4/5] jar + d8"
jar cfe "$BUILD/helper.jar" re.gsvc.Helper -C "$BUILD/classes" .
"$D8" --lib "$ANDROID_JAR" --min-api 19 --output "$BUILD" "$BUILD/helper.jar"
DEX="$BUILD/classes.dex"
if [ ! -f "$DEX" ]; then
  echo "d8 未产出 classes.dex" >&2
  exit 1
fi

# 5. 覆盖检入的 helper.dex
echo "[5/5] 覆盖 $HELPER_DIR/helper.dex"
cp "$DEX" "$HELPER_DIR/helper.dex"
ls -l "$HELPER_DIR/helper.dex"
echo "完成。重新编译 frida-server 即可内嵌新 helper（spawn 模式可用）。"
