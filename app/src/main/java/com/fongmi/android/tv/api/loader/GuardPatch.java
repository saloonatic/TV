package com.fongmi.android.tv.api.loader;

import android.os.Build;
import android.util.Log;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * GuardPatch —— 给第三方爬虫 jar 里「加固壳」的 .so 打 Android 4.3 兼容补丁。
 *
 * <p>背景（实测数据见 GuardSO_4.3实测记录.md）：
 * 饭太硬 / 菜妮丝 / 余生 / 牛播一 这几个源用的是同一款 dex 保护壳（ftyguard_vN.so）。
 * 壳在 native 里用反射查 {@code android.content.Context.getCodeCacheDir()}
 * 来拿「放解密后 dex 的目录」——而这个方法是 <b>API 21 (Android 5.0) 才加的</b>。
 * 在 4.3 上 GetMethodID 直接返回 NULL，壳随后用这个 NULL methodID 调方法：
 * <ul>
 *   <li>开了 CheckJNI 的模拟器：Dalvik 直接 dvmAbort（tombstone 里 pc 落在 .so 内）；</li>
 *   <li>真机（无 CheckJNI）：解引用 NULL+0x2c → SIGSEGV，整个进程被杀。</li>
 * </ul>
 *
 * <p>壳的字符串表在 .data 里，规则是<b>每条字符串一个固定单字节 XOR</b>。
 * 所以只要把 "getCodeCacheDir"(15 字节) 原地改成 "getCacheDir"+5 个 NUL(16 字节)，
 * 用同一个 key 重新异或回去，壳就会去查 {@code getCacheDir()}（API 1 就有，语义也一致：
 * 都是 App 可写的缓存目录）。实测改完 4.3 ARM 模拟器上不再崩溃。
 *
 * <p><b>第二层（v269）：</b>壳把解出来的内容写到 {@code <cache>/sharedb/config.db}，
 * 然后用 {@code DexClassLoader} 加载它。4.3 的 {@code DexPathList.makeDexElements}
 * 对文件<b>按后缀白名单分流</b>（{@code .dex} / {@code .jar} / {@code .zip} / {@code .apk}），
 * 后缀不在名单里的<b>静默丢弃、连试都不试</b>，于是 {@code dexElements.length == 0}，
 * 随后 {@code Class.forName("...InitOrigin")} 找不到类 → {@code BaseSpiderGuard.init} NPE。
 *
 * <p>实测矩阵（同一份字节，只换文件名，4.3 ARM 模拟器）：
 * <pre>
 *   real.dex     裸 dex   .dex  → 1
 *   zipdex.dex   zip      .dex  → 1   ← 内容不用动，后缀对就行
 *   cfg.db       zip      .db   → 0   ← 白名单外，直接丢
 *   cfg2.db      裸 dex   .db   → 0
 * </pre>
 * 所以只要把字符串表里的 {@code "config.db"} 原地换成等长的 {@code "guard.dex"}
 * （9 → 9 字节，终结符位置都不用动），壳自己写出来的就是 {@code guard.dex}，
 * 4.3 会先按裸 dex 打开失败、再按 jar 打开成功——内容和原来一模一样。
 *
 * <p>为什么不用「运行时抢改 cache 里的 .so」：
 * 壳是 mmap 之后立刻 dlopen，抢改会让文件页失效 → SIGBUS（实测 tombstone_06）。
 * 所以必须在 jar 落盘后、被加载前改，也就是这里。
 */
public final class GuardPatch {

    private static final String TAG = "GuardPatch";
    private static final Charset ASCII = Charset.forName("US-ASCII");

    /** 壳要找的方法名（明文） */
    private static final byte[] FROM = "getCodeCacheDir".getBytes(ASCII);
    /** 替换成 4.3 就有的同名语义方法；总长 16 字节，多出来的用 NUL 补齐 */
    private static final byte[] TO = "getCacheDir\0\0\0\0\0".getBytes(ASCII);

    /**
     * 壳落盘的 dex 文件名。必须改成 4.3 {@code DexPathList} 认的后缀（等长，9 → 9）。
     * 只对 {@code .so} 生效——{@code .guard} 里是真 dex 的 deflate 流，不能碰。
     *
     * <p>选 {@code .jar} 而不是 {@code .dex}：改成 {@code .dex} 后，4.3 的
     * {@code DexPathList.optimizedPathFor} 看到「已经以 .dex 结尾」就把名字<b>原样</b>拿去当
     * odex 输出名，一旦壳传的优化目录就是源目录，输出路径会和源文件撞成同一个文件；
     * {@code .jar} 会被换成 {@code guard.dex} 放在优化目录里，不冲突，
     * 而且「zip + classes.dex + .jar 后缀」正是 4.3 处理得最标准的一条路
     * （fty 自己的爬虫包就是这么加载的）。
     */
    private static final byte[] DB_FROM = "config.db".getBytes(ASCII);
    private static final byte[] DB_TO = "guard.jar".getBytes(ASCII);

    /**
     * 本进程内已修过的 jar，避免第二次进来时「找不到特征」被误判成不可修。
     *
     * <p>⚠️ 这里必须记「路径 + 长度 + 修改时间」，<b>不能只记路径</b>：
     * 切源时 JarLoader 会把这个 jar 重新下载一遍并<b>覆盖同名缓存文件</b>（实测每次切源都重下），
     * 覆盖后的内容又是原始未打补丁的 .so。只按路径记的话第二次会直接返回 true 放行，
     * 于是又崩在 SIGSEGV @0x2c —— 这正是 v267「先切肥猫再切回饭太硬就闪退」的原因。
     */
    private static final Set<String> DONE = Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>());

    /** 文件身份签名：内容被重新下载覆盖时长度/时间必然变化 */
    private static String sig(File f) {
        return f.getAbsolutePath() + "|" + f.length() + "|" + f.lastModified();
    }

    private GuardPatch() {
    }

    /**
     * 反射读 {@code BaseDexClassLoader.pathList.dexElements.length}。
     * 只为诊断：4.3 的 {@code DexPathList.makeDexElements} 会把后缀不认识的文件
     * <b>静默丢进空列表</b>，不做任何提示，只能这样看出来。
     *
     * @return 元素个数；反射失败返回 -1
     */
    public static int elemCount(dalvik.system.BaseDexClassLoader cl) {
        try {
            java.lang.reflect.Field f = dalvik.system.BaseDexClassLoader.class.getDeclaredField("pathList");
            f.setAccessible(true);
            Object pl = f.get(cl);
            java.lang.reflect.Field fe = pl.getClass().getDeclaredField("dexElements");
            fe.setAccessible(true);
            return java.lang.reflect.Array.getLength(fe.get(pl));
        } catch (Throwable t) {
            return -1;
        }
    }

    /**
     * 就地修补 jar 里所有 .so 条目。没有命中就不动文件。
     *
     * @return true 表示这个 jar 的内嵌 so 已经/刚刚被修好，调用方可以放行加载
     */
    public static boolean apply(File jar) {
        if (jar == null || !jar.exists()) return false;
        if (Build.VERSION.SDK_INT >= 21) return false;      // 5.0+ 原生有这个 API，不需要也不该改
        long len = jar.length();
        if (len < 1024 || len > 64L * 1024 * 1024) return false; // 明显不是 jar / 太大，不折腾
        // 已经修过的「同一份文件」直接放行；文件被重新下载覆盖后签名变化，会重新扫一遍
        if (DONE.contains(sig(jar))) return true;

        ZipFile zin = null;
        File tmp = null;
        try {
            zin = new ZipFile(jar);
            List<String> names = new ArrayList<String>();
            List<byte[]> datas = new ArrayList<byte[]>();
            List<Integer> methods = new ArrayList<Integer>();
            List<Long> times = new ArrayList<Long>();
            int hits = 0;
            int pre = 0;

            Enumeration<? extends ZipEntry> es = zin.entries();
            while (es.hasMoreElements()) {
                ZipEntry e = es.nextElement();
                byte[] d = read(zin.getInputStream(e));
                if (d == null) return false;               // 读失败就整体放弃，别把 jar 写坏
                if (isNative(e.getName())) {
                    pre += countPatched(d, TO);
                    hits += patch(d, FROM, TO);
                    if (e.getName().toLowerCase().endsWith(".so")) {
                        pre += countPatched(d, DB_TO);
                        hits += patch(d, DB_FROM, DB_TO);
                    }
                }
                names.add(e.getName());
                datas.add(d);
                methods.add(e.getMethod());
                times.add(e.getTime());
            }
            if (hits == 0) {
                // 文件本身已经是打过补丁的（例如上次改完后缓存没被重新下载），
                // 这种情况要放行，不能当成「修不了」跳过。
                if (pre > 0) {
                    DONE.add(sig(jar));
                    Log.e(TAG, "guard already patched (" + pre + " site(s)), allow: " + jar.getName());
                    return true;
                }
                return false;
            }

            tmp = new File(jar.getParentFile(), jar.getName() + ".gp");
            ZipOutputStream out = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(tmp)));
            for (int i = 0; i < names.size(); i++) {
                byte[] d = datas.get(i);
                ZipEntry n = new ZipEntry(names.get(i));
                if (times.get(i) > 0) n.setTime(times.get(i));
                if (methods.get(i) == ZipEntry.STORED) {
                    CRC32 c = new CRC32();
                    c.update(d, 0, d.length);
                    n.setMethod(ZipEntry.STORED);
                    n.setSize(d.length);
                    n.setCompressedSize(d.length);
                    n.setCrc(c.getValue());
                } else {
                    n.setMethod(ZipEntry.DEFLATED);
                }
                out.putNextEntry(n);
                out.write(d);
                out.closeEntry();
            }
            out.close();
            zin.close();
            zin = null;
            if (!tmp.renameTo(jar)) {
                copy(tmp, jar);
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
            tmp = null;
            DONE.add(sig(jar));
            Log.e(TAG, "guard patched " + hits + " site(s): " + jar.getName());
            return true;
        } catch (Throwable t) {
            Log.e(TAG, "guard patch failed: " + jar.getName() + " <- " + t);
            if (tmp != null) {
                //noinspection ResultOfMethodCallIgnored
                tmp.delete();
            }
            return false;
        } finally {
            if (zin != null) try {
                zin.close();
            } catch (Throwable ignored) {
            }
        }
    }

    private static boolean isNative(String name) {
        String n = name.toLowerCase();
        return n.endsWith(".so") || n.endsWith(".guard");
    }

    /**
     * 扫描并原地改写。返回命中次数。
     * 规则：整串按单字节 key 异或，且结尾那个 NUL 用同一个 key 加密。
     * {@code to} 长度必须 &gt;= {@code from} 长度；超出的部分写成 NUL（沿用同一个 key）。
     */
    private static int patch(byte[] b, byte[] from, byte[] to) {
        int hits = 0;
        for (int i = 0; i + from.length < b.length; i++) {
            int k = (b[i] ^ from[0]) & 0xff;
            boolean ok = true;
            for (int j = 1; j < from.length; j++) {
                if (((b[i + j] ^ k) & 0xff) != (from[j] & 0xff)) {
                    ok = false;
                    break;
                }
            }
            if (!ok) continue;
            if (((b[i + from.length] ^ k) & 0xff) != 0) continue;   // 后面不是字符串结尾，不动
            for (int j = 0; j < to.length; j++) b[i + j] = (byte) (to[j] ^ k);
            hits++;
            i += to.length - 1;
        }
        return hits;
    }

    /**
     * 数一下这条 .so 里已经有多少处被改成了 {@code to}。
     * 只用于识别「上次已经修过、这次没被重新下载覆盖」的文件，避免把它当成修不了而跳过。
     */
    private static int countPatched(byte[] b, byte[] to) {
        int hits = 0;
        for (int i = 0; i + to.length <= b.length; i++) {
            int k = (b[i] ^ to[0]) & 0xff;
            boolean ok = true;
            for (int j = 1; j < to.length; j++) {
                if (((b[i + j] ^ k) & 0xff) != (to[j] & 0xff)) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                hits++;
                i += to.length - 1;
            }
        }
        return hits;
    }

    private static byte[] read(InputStream is) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(64 * 1024);
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        } catch (Throwable t) {
            return null;
        } finally {
            try {
                is.close();
            } catch (Throwable ignored) {
            }
        }
    }

    private static void copy(File from, File to) throws Exception {
        InputStream is = new FileInputStream(from);
        OutputStream os = new FileOutputStream(to);
        try {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) os.write(buf, 0, n);
            os.flush();
        } finally {
            try {
                is.close();
            } catch (Throwable ignored) {
            }
            try {
                os.close();
            } catch (Throwable ignored) {
            }
        }
    }
}
