#!/usr/bin/env bash
# mkcompat.sh — 重建 app/libs/compat-api18.jar（API18 缺失的 java.* 类垫片）
#
# 为什么需要：Android 4.3 的 libcore 里没有 API19+ 的类，第三方爬虫 dex 一旦引用就
# NoClassDefFoundError。App 把同名类打进自己的 dex，PathClassLoader 先问 BootClassLoader
# （找不到）就落到本地 dex，于是补上了。
#
# 为什么源码包名是 jawa.*：javac(JDK9+) 禁止编译 java.*。编译完把 class 里的
# "jawa" 字节换成同长度的 "java" 即可，常量池长度字段不用动。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BT=/sdk/build-tools/33.0.2
AJ=/sdk/platforms/android-33/android.jar
OUT="$HERE/out"
JAR="$HERE/../app/libs/compat-api18.jar"

rm -rf "$OUT"
mkdir -p "$OUT/classes" "$OUT/keep"

# 1) 先把现成 jar 里的类全部解出来（StandardCharsets / Base64 等）
cd "$OUT/keep" && jar xf "$JAR"

# 2) 编译 jawa.* 源码
javac --release 8 -nowarn -encoding UTF-8 -cp "$AJ" -d "$OUT/classes" \
  $(find "$HERE/src" -name '*.java')
echo "  编译完成"

# 3) jawa -> java（等长替换），落到 keep/
python3 - "$OUT" <<'PY'
import os, shutil, sys
out = sys.argv[1]
src, dst = os.path.join(out, 'classes'), os.path.join(out, 'keep')
n = 0
for root, _, files in os.walk(src):
    for f in files:
        if not f.endswith('.class'):
            continue
        p = os.path.join(root, f)
        rel = os.path.relpath(p, src)
        data = open(p, 'rb').read()
        cnt = data.count(b'jawa')
        assert cnt > 0, p
        data = data.replace(b'jawa', b'java')
        target = os.path.join(dst, rel.replace('jawa' + os.sep, 'java' + os.sep, 1)
                             if rel.startswith('jawa' + os.sep) else rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        open(target, 'wb').write(data)
        n += 1
        print('  %s  (%d 处 jawa->java)' % (rel, cnt))
print('  共 %d 个 class' % n)
PY

# 4) 重新打包
rm -f "$JAR"
cd "$OUT/keep" && jar cf "$JAR" .
echo "  -> $JAR"
unzip -l "$JAR" | sed -n '1,20p'
