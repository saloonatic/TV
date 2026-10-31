#!/usr/bin/env bash
# mkjar.sh — 重建 catvod/libs/javax-compat.jar（API18 缺失的 javax.* 类垫片）
#
# 为什么需要：Android 4.3 没有 javax.crypto.spec.GCMParameterSpec（API 19 才有）。
# 大量爬虫用 AES/GCM/NoPadding 解自己的接口数据，4.3 上 new 它直接 NoClassDefFoundError，
# 而多数爬虫在子线程里裸调、没人 catch → 整进程崩（实测「点分类整机闪退」就是这么来的）。
#
# 为什么打包成 jar 而不是直接放源码：放源码会与 compileSdk 的 android.jar 里的同名类
# 在 javac 阶段冲突（duplicate class）。打成 jar 走 classpath，编译期用 android.jar 的，
# 运行期 4.3 找不到才回落到本地 dex —— 正好是我们要的行为。
#
# 用法：./mkjar.sh   （需要 android.jar；容器里是 /sdk/platforms/android-33/android.jar）
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
AJ="${ANDROID_JAR:-/sdk/platforms/android-33/android.jar}"
OUT="$HERE/out"
JAR="$HERE/javax-compat.jar"

rm -rf "$OUT"
mkdir -p "$OUT"

javac --release 8 -nowarn -encoding UTF-8 -cp "$AJ" -d "$OUT" \
    $(find "$HERE/src" -name '*.java')
echo "  编译完成"

rm -f "$JAR"
cd "$OUT" && jar cf "$JAR" .
echo "  -> $JAR"
unzip -l "$JAR"
