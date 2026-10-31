package com.fongmi.android.tv.api.loader;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import com.fongmi.android.tv.App;
import com.fongmi.android.tv.api.Decoder;
import com.fongmi.android.tv.utils.Notify;
import com.fongmi.android.tv.utils.UrlUtil;
import com.github.catvod.crawler.Spider;
import com.github.catvod.crawler.SpiderNull;
import com.github.catvod.net.OkHttp;
import com.github.catvod.utils.Path;
import com.github.catvod.utils.Util;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.DexClassLoader;

public class JarLoader {

    // 同一 URL 失败后 10 分钟内不再重试：一次切源会按分类/线路多次调用 getSpider，
    // 而 parseJar 的防重只在成功后生效，失败时每次都会重打 3 次请求（日志里出现过 6 轮 × 3 次）。
    private static final long FAIL_TTL = 10 * 60 * 1000L;
    // 同一域名 5 分钟内只弹一次 Toast，避免 6 个提示连弹糊在屏幕上
    private static final long NOTIFY_TTL = 5 * 60 * 1000L;

    /**
     * 进程级：已经成功 {@code Init.init} 过的加固壳 jar → 当时的 DexClassLoader。
     *
     * <p><b>为什么必须是进程级静态、且 key 只用绝对路径：</b>壳（ftyguard/wexguard 家族）
     * 的 .so 在一个进程里只会跑一次 {@code JNI_OnLoad}，全局状态（JavaVM、缓存的 jclass、
     * 解密上下文）就在那一次建立。而 {@code VodConfig.load()} 切配置时会走
     * {@code BaseLoader.get().clear()} → 这里 {@code clear()} 把 {@code loaders} 清空，
     * 于是同一个 jar 被重新 {@code new DexClassLoader} + 重新 {@code Init.init} ——
     * 第二次壳拿着已失效的全局引用去调 JNIEnv 函数，即空指针解引用。
     *
     * <p>真机 2026-10-31 17:08:08 实证（pid 10329 / tid 10983 / pool-1-thread-1）：
     * <pre>
     *   signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0000002c   ← r0 = 0
     *   #00 pc 0004cf38 /system/lib/libdvm.so
     *   #01 pc 00011307 /data/data/com.fongmi.android.tv/cache/.ftyfnwognrd38ira
     * </pre>
     * 对照 diag.log：16:56:38 同一个 3bb7a6b0.jar 首次 init 成功；17:07:52 切配置 clear；
     * 17:08:06 二次 init；17:08:08 崩。进程重启后 17:08:14 再 init 又成功了。
     */
    private static final ConcurrentHashMap<String, DexClassLoader> GUARD_INITED = new ConcurrentHashMap<>();

    /** 串行化「打补丁 + 建 loader + Init.init」整段，避免两个线程同时首次初始化同一个壳。 */
    private static final Object GUARD_LOCK = new Object();

    private final ConcurrentHashMap<String, DexClassLoader> loaders;
    private final ConcurrentHashMap<String, Method> methods;
    private final ConcurrentHashMap<String, Spider> spiders;
    private final ConcurrentHashMap<String, Long> failed;
    private final ConcurrentHashMap<String, Long> notified;
    private String recent;

    public JarLoader() {
        loaders = new ConcurrentHashMap<>();
        methods = new ConcurrentHashMap<>();
        spiders = new ConcurrentHashMap<>();
        failed = new ConcurrentHashMap<>();
        notified = new ConcurrentHashMap<>();
    }

    /**
     * 切配置时调用。注意：<b>不能</b>顺手清 {@link #GUARD_INITED} —— 那里存的是壳在
     * native 侧已经建立好的全局状态所对应的 loader，清了就等于下次重新 {@code Init.init}，
     * 而那正是 17:08 那次 SIGSEGV 的成因。这里只清「本实例的缓存视图」。
     */
    public void clear() {
        for (Spider spider : spiders.values()) App.execute(spider::destroy);
        loaders.clear();
        methods.clear();
        spiders.clear();
    }

    public void setRecent(String recent) {
        this.recent = recent;
    }

    private void load(String key, File file) {
        // 诊断补丁：文件不存在/为空时不要建 DexClassLoader。
        // 否则后续所有 loadClass 都是 ClassNotFoundException，而调用方只看到 SpiderNull，
        // 表现就是「切源后无任何提示、首页也不刷新」——完全静默，无法定位。
        if (file == null || !file.exists() || file.length() == 0) {
            diag("jar missing, skip load: " + (file == null ? "null" : file.getAbsolutePath()));
            return;
        }

        // ★ 壳复用：本进程里这个加固 jar 已经成功 Init.init 过，就只把旧 loader 挂回去，
        // 绝不再 init 第二次（详见 GUARD_INITED 注释）。切配置 → clear() → 再 load 是同一条路。
        // key 用**文件内容 md5** 而不是路径：同一个源换个 URL 写法（加 query、大小写、重定向）
        // 会落到不同的缓存文件名上，但字节一模一样、壳也是同一个，路径 key 就漏了。
        String pin = pinKey(file);
        DexClassLoader inited = GUARD_INITED.get(pin);
        if (inited != null) {
            loaders.put(key, inited);
            diag("reuse guard-inited loader, skip 2nd Init.init: " + file.getName());
            putProxy(key);
            return;
        }

        // 防护补丁：部分源爬虫（饭太硬/王二小等）内嵌 guard .so，在 Android 4.x 上
        // System.load 时 SIGSEGV（native 信号 try/catch 捕获不到），必须预检跳过。
        // 运行期开关：files/allow_native 存在则放行，用于实测这些 .so 到底能不能在 4.3 上跑。
        boolean allowNative = new File(App.get().getFilesDir(), "allow_native").exists();
        boolean guardNative = false;
        if (Build.VERSION.SDK_INT < 21 && hasNativeLib(file)) {
            // 先试着给「加固壳」的 .so 打 4.3 兼容补丁（getCodeCacheDir -> getCacheDir）。
            // 饭太硬/菜妮丝/余生/牛播一 都是用 Context.getCodeCacheDir()（API 21）拿解密目录，
            // 4.3 上拿到 NULL methodID → 原生崩溃。改完就能正常跑（ARM 模拟器已实测）。
            // 注意：这里不能因为 files/allow_native 存在就跳过打补丁 —— 那个开关只决定
            // 「修不了的壳要不要硬上」，否则等于把唯一能救的一类也放过。
            if (GuardPatch.apply(file)) {
                guardNative = true;
                Log.e("JarLoader", "guard patched, load native on API<21: " + file.getName());
                diag("guard patched, load native on API<21: " + file.getName());
            } else if (!allowNative) {
                Log.e("JarLoader", "skip jar with embedded native lib on API<21: " + file.getName());
                diag("skip jar with embedded native lib on API<21: " + file.getName());
                App.post(() -> Notify.show("该源内置原生库，Android 4.x 不支持，已跳过"));
                return;
            } else {
                guardNative = true;
                Log.e("JarLoader", "native allowed by flag (unpatchable): " + file.getName());
                diag("native allowed by flag (unpatchable): " + file.getName());
            }
        }
        final DexClassLoader loader;
        synchronized (GUARD_LOCK) {
            // 双检：并发的另一线程可能刚 init 完同一个壳，这里必须再看一次。
            DexClassLoader again = GUARD_INITED.get(pin);
            if (again != null) {
                loaders.put(key, again);
                diag("reuse guard-inited loader (concurrent), skip 2nd Init.init: " + file.getName());
                putProxy(key);
                return;
            }
            loader = new DexClassLoader(file.getAbsolutePath(), Path.jar().getAbsolutePath(), null, App.get().getClassLoader());
            loaders.put(key, loader);
            // 诊断：dexElements 是否为 0（4.3 的 DexPathList 会按后缀静默丢弃文件），
            // 以及壳解出来的类到底在不在——这两条是「切源无反应」最常见的两个根因。
            diag("loader ready: " + file.getName() + " elem=" + GuardPatch.elemCount(loader));
            try {
                loader.loadClass("com.github.catvod.spider.InitOrigin");
                diag("  InitOrigin present");
            } catch (Throwable e) {
                diag("  InitOrigin MISSING", e);
            }
            purgeGuardOdex();
            if (guardNative && invokeInit(key)) {
                // init 成功才钉住；失败的不缓存，留给下次重试（壳崩的时候进程已经没了，不在此列）
                GUARD_INITED.put(pin, loader);
                diag("guard loader pinned for process lifetime: " + file.getName());
            }
        }
        putProxy(key);
        diagGuardLoader(loader);
    }

    /**
     * 诊断壳自己的那个 DexClassLoader（{@code Init.loader()}）到底有没有造出来。
     *
     * <p>加固包的调用链是：{@code Init.init(ctx)} → native {@code DexNative.getLoader(ctx)}
     * 解出真 dex 并 new 一个 DexClassLoader 存进 {@code Init.loader}；随后
     * {@code BaseSpiderGuard.&lt;init&gt;} 里 {@code Init.getSpider(getClass().getName())}
     * 用这个 loader 反射出真正的爬虫类。任一步失败都只表现为
     * {@code BaseSpiderGuard.init} 的 NPE（delegate 字段是 null），原始异常被吞掉。
     */
    private void diagGuardLoader(DexClassLoader jarLoader) {
        try {
            Class<?> init = jarLoader.loadClass("com.github.catvod.spider.Init");
            Object l = init.getMethod("loader").invoke(null);
            diag("  Init.loader -> " + l);
            if (!(l instanceof ClassLoader)) return;
            ClassLoader gl = (ClassLoader) l;
            if (l instanceof BaseDexClassLoader) diag("  guard loader elem=" + GuardPatch.elemCount((BaseDexClassLoader) l));
            try {
                Class<?> c = gl.loadClass("com.github.catvod.spider.InitOrigin");
                diag("  guard InitOrigin OK, loader=" + c.getClassLoader());
            } catch (Throwable t) {
                diag("  guard InitOrigin FAIL", t);
            }
        } catch (Throwable t) {
            diag("  Init.loader reflect FAIL", t);
        }
    }

    private boolean hasNativeLib(File file) {
        ZipFile zip = null;
        try {
            zip = new ZipFile(file);
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                if (entries.nextElement().getName().endsWith(".so")) return true;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        } finally {
            if (zip != null) try {
                zip.close();
            } catch (Exception ignored) {
            }
        }
        return false;
    }

    /**
     * 壳把解密结果固定落在 {@code cache/sharedb/guard.jar}，**所有加固源共用这一个路径**。
     *
     * <p>切源时后一个壳会覆盖这个文件，dalvik 随即发现随行的 {@code guard.dex}（odex）已过期，
     * 就 <b>就地 truncate 然后重写</b>它。而前一个源在 {@code Init.loader} 里留下的
     * {@code DexClassLoader} 仍映射着那份 odex——页一旦被截断，再在 {@code strcmp} 里
     * 查类名就是 {@code SIGBUS (BUS_ADRERR)}。
     *
     * <p>真机 2026-10-31 16:38 崩过一次，日志严丝合缝：
     * <pre>
     *   I/dalvikvm: DexOpt: source file mod time mismatch (5d5d6f73 vs 5d45896e)
     *   W/dalvikvm(7753): DexOpt: method is in an interface     ← fork 出去的 dexopt 子进程
     *   F/libc    : Fatal signal 7 (SIGBUS) at 0x66870324 (code=2), thread pool-1-thread-5
     *   #00 strcmp+244  #01 libdvm.so
     * </pre>
     * 前一轮（16:36）用的是 fty 系壳，这一轮（16:38）换成 wex 系壳，两者 guard 内容不同、
     * 却写同一个 {@code guard.jar}，于是触发 odex 重写。
     *
     * <p>对策：在壳重新 dexopt 之前先把旧 odex <b>unlink</b> 掉。unlink 只摘目录项，
     * 旧 inode 因为仍被映射而保持有效（页全在），新 dexopt 写的是另一个 inode，
     * 两者互不干扰。换成 {@code truncate} 或"先读全部再重写"都不行，必须删。
     *
     * <p>代价为零：dalvik 发现 odex 过期后本来也要重新 dexopt，这里只是把
     * 「原地重写」换成「换一个 inode 重写」。
     */
    private static void purgeGuardOdex() {
        File dir = new File(App.get().getCacheDir(), "sharedb");
        // 两个都要删：
        //   guard.dex —— dalvik 会就地 truncate 重写过期 odex
        //   guard.jar —— 壳自己用 FileOutputStream 覆盖写（同样是 truncate）
        // 任何一份被截断，上一轮 loader 的映射页都会失效。
        for (String name : new String[]{"guard.dex", "guard.jar"}) {
            File f = new File(dir, name);
            if (!f.exists()) continue;
            long len = f.length();
            if (f.delete()) {
                diag("purged " + name + " (" + len + "B) to avoid SIGBUS on re-dexopt");
            } else {
                diag("purge " + name + " FAILED, may SIGBUS on source switch: " + f);
            }
        }
    }

    /**
     * 壳的「进程身份」：优先用文件内容 md5（同一份字节换个文件名也算同一个壳），
     * 算不出来时退回绝对路径。1~2MB 的文件读一遍，相对它后面几分钟的解密+dexopt 可以忽略。
     */
    private static String pinKey(File file) {
        String md5 = Util.md5(file);
        return md5 == null || md5.isEmpty() ? file.getAbsolutePath() : md5;
    }

    /** @return true 表示壳自己的 {@code Init.init} 跑完了（加固包 → 真 dex 已解出并挂上 loader） */
    private boolean invokeInit(String key) {
        try {
            Class<?> clz = loaders.get(key).loadClass("com.github.catvod.spider.Init");
            Method method = clz.getMethod("init", Context.class);
            method.invoke(clz, App.get());
            diag("spider Init.init ok: " + key);
            return true;
        } catch (Throwable e) {
            diag("spider Init.init FAIL: " + key, e);
            return false;
        }
    }

    private void putProxy(String key) {
        try {
            Class<?> clz = loaders.get(key).loadClass("com.github.catvod.spider.Proxy");
            Method method = clz.getMethod("proxy", Map.class);
            methods.put(key, method);
        } catch (Throwable e) {
            diag("spider Proxy.proxy FAIL: " + key, e);
        }
    }

    // 诊断补丁：原实现在下载失败时 catch 住异常、直接返回一个「并不存在」的文件路径，
    // 上层照样 new DexClassLoader → 全类 ClassNotFoundException → SpiderNull，
    // 用户侧表现为「切源没反应、首页不刷新、也没有任何报错」。这里改为：重试 + 落日志 + 返回 null。
    private File download(String url) {
        Long t = failed.get(url);
        if (t != null) {
            if (System.currentTimeMillis() - t < FAIL_TTL) {
                diag("jar skip, failed recently: " + url);
                return null;
            }
            failed.remove(url);
        }
        long start = System.currentTimeMillis();
        Exception last = null;
        for (int i = 1; i <= 2; i++) {
            try {
                byte[] data = OkHttp.newCall(url).execute().body().bytes();
                if (data == null || data.length == 0) throw new IOException("empty body");
                File file = Path.write(Path.jar(url), data);
                diag("jar ok #" + i + " (" + (System.currentTimeMillis() - start) + "ms, " + data.length + " bytes) " + url);
                failed.remove(url);
                return file;
            } catch (Exception e) {
                last = e;
                diag("jar fail #" + i + " (" + (System.currentTimeMillis() - start) + "ms) " + url + " <- " + e);
            }
        }
        // OkHttp 失败时用系统 HttpURLConnection 再试一次（API18 上两者的 TLS/DNS 行为可能不同）
        File plain = downloadPlain(url);
        if (plain != null) return plain;
        diag("jar download gave up: " + url + " <- " + last);
        failed.put(url, System.currentTimeMillis());
        return null;
    }

    private File downloadPlain(String url) {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(30000);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Linux; Android 4.3) AppleWebKit/537.36");
            int code = conn.getResponseCode();
            if (code != 200) throw new IOException("HTTP " + code);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            InputStream is = conn.getInputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) bos.write(buf, 0, n);
            is.close();
            byte[] data = bos.toByteArray();
            if (data.length == 0) throw new IOException("empty body");
            File file = Path.write(Path.jar(url), data);
            diag("jar ok by HttpURLConnection (" + data.length + " bytes) " + url);
            return file;
        } catch (Throwable e) {
            diag("jar fail by HttpURLConnection " + url + " <- " + e);
            return null;
        } finally {
            if (conn != null) try {
                conn.disconnect();
            } catch (Throwable ignored) {
            }
        }
    }

    // 同时输出到 logcat 和 diag.log。
    // ⚠️ 4.3 模拟器的 /sdcard 是只读的（Read-only file system），写 /sdcard 会静默失败，
    // 所以主通道必须是 App 私有目录 files/diag.log；/sdcard 那份只当老电视上的附加副本。
    private static void diag(String msg) {
        Log.e("JarLoader", msg);
        String line = new SimpleDateFormat("MM-dd HH:mm:ss", Locale.US).format(new Date()) + " " + msg + "\n";
        try {
            FileWriter w = new FileWriter(new File(App.get().getFilesDir(), "diag.log"), true);
            w.write(line);
            w.close();
        } catch (Throwable ignored) {
        }
        try {
            FileWriter w = new FileWriter("/sdcard/fongmi_diag.log", true);
            w.write(line);
            w.close();
        } catch (Throwable ignored) {
        }
    }

    /** 给别的类用的诊断出口（4.3 没有 logcat，只能落文件）。 */
    public static void note(String msg) {
        diag(msg);
    }

    /** 给别的类用的诊断出口（4.3 没有 logcat，只能落文件）。 */
    public static void note(String what, Throwable e) {
        diag(what, e);
    }

    /** 把异常连同「第一处调用方」记下来——4.3 上没有 logcat，printStackTrace 等于扔掉。 */
    private static void diag(String what, Throwable e) {
        if (e == null) {
            diag(what + " <- null");
            return;
        }
        StackTraceElement[] st = e.getStackTrace();
        String at = (st != null && st.length > 0) ? (" @ " + st[0]) : "";
        diag(what + " <- " + e.getClass().getName() + ": " + e.getMessage() + at);
    }

    private void notifyFail(String url) {
        String host = url;
        try {
            host = new URL(url).getHost();
        } catch (Throwable ignored) {
        }
        long now = System.currentTimeMillis();
        Long last = notified.get(host);
        if (last != null && now - last < NOTIFY_TTL) {
            diag("notify suppressed for host: " + host);
            return;
        }
        notified.put(host, now);
        final String h = host;
        App.post(() -> Notify.show("源爬虫包下载失败（" + h + "），该源可能已失效，请换源"));
    }

    public synchronized void parseJar(String key, String jar) {
        if (loaders.containsKey(key)) return;
        String[] texts = jar.split(";md5;");
        String md5 = texts.length > 1 ? texts[1].trim() : "";
        jar = texts[0];
        if (md5.length() > 0 && Util.equals(jar, md5)) {
            // 诊断补丁：缓存 jar 缺失时（清过缓存/装包覆盖后），原逻辑会一直用不存在的缓存路径，
            // 表现为该源永久失效且无提示。这里改为缓存缺失就重新下载。
            File cache = Path.jar(jar);
            if (cache.exists() && cache.length() > 0) {
                load(key, cache);
            } else if (jar.startsWith("http")) {
                File file = download(jar);
                if (file == null) notifyFail(jar);
                else load(key, file);
            }
        } else if (jar.startsWith("img+")) {
            load(key, Decoder.getSpider(jar));
        } else if (jar.startsWith("http")) {
            File file = download(jar);
            if (file == null) notifyFail(jar);
            else load(key, file);
        } else if (jar.startsWith("file")) {
            load(key, Path.local(jar));
        } else if (jar.startsWith("assets")) {
            parseJar(key, UrlUtil.convert(jar));
        } else if (!jar.isEmpty()) {
            parseJar(key, UrlUtil.convert(jar));
        }
    }

    public Spider getSpider(String key, String api, String ext, String jar) {
        try {
            String jaKey = Util.md5(jar);
            String spKey = jaKey + key;
            if (spiders.containsKey(spKey)) return spiders.get(spKey);
            if (!loaders.containsKey(jaKey)) parseJar(jaKey, jar);
            DexClassLoader loader = loaders.get(jaKey);
            if (loader == null) {
                // 原来是直接 loaders.get(jaKey).loadClass(...) → NPE，
                // 被外层 catch 吞掉后只剩一个毫无信息的 SpiderNull
                diag("spider unavailable, jar not loaded: " + jar);
                return new SpiderNull();
            }
            Spider spider = (Spider) loader.loadClass("com.github.catvod.spider." + api.split("csp_")[1]).newInstance();
            spider.init(App.get(), ext);
            spiders.put(spKey, spider);
            return spider;
        } catch (Throwable e) {
            diag("getSpider FAIL key=" + key + " api=" + api, e);
            return new SpiderNull();
        }
    }

    public JSONObject jsonExt(String key, LinkedHashMap<String, String> jxs, String url) throws Throwable {
        Class<?> clz = loaders.get(recent).loadClass("com.github.catvod.parser.Json" + key);
        Method method = clz.getMethod("parse", LinkedHashMap.class, String.class);
        return (JSONObject) method.invoke(null, jxs, url);
    }

    public JSONObject jsonExtMix(String flag, String key, String name, LinkedHashMap<String, HashMap<String, String>> jxs, String url) throws Throwable {
        Class<?> clz = loaders.get(recent).loadClass("com.github.catvod.parser.Mix" + key);
        Method method = clz.getMethod("parse", LinkedHashMap.class, String.class, String.class, String.class);
        return (JSONObject) method.invoke(null, jxs, name, flag, url);
    }

    public Object[] proxyInvoke(Map<String, String> params) {
        try {
            Method method = methods.get(Util.md5(recent));
            if (method == null) return null;
            return (Object[]) method.invoke(null, params);
        } catch (Throwable e) {
            e.printStackTrace();
            return null;
        }
    }
}
