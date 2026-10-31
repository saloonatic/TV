package com.fongmi.android.tv.utils;

import android.os.Build;
import android.util.Log;

/**
 * 4.3 原生兼容垫片。
 * <p>
 * 背景：Android 4.3 的 /system/lib/libdl.so 里 {@code dladdr} 是个 4 字节的空桩
 * （{@code movs r0,#0; bx lr}，永远返回 0 且不写 Dl_info）。而源里那些 guard .so
 * （饭太硬 / 王二小 / 菜妮丝 / 余生 / 牛播一 的 ftyguard、摸鱼的 FishGuard）
 * 都拿 dladdr 的结果去定位自己，拿到 0 之后按 offset 解引用 → SIGSEGV，
 * 而且崩在子线程的 native 调用里，Java 侧 try/catch 完全接不住，只能整进程死。
 * <p>
 * 这里在 Application 启动最早期把自己实现的 dladdr 载进全局符号表。老 bionic 的符号
 * 查找走 solist（新加载的排在前面），先加载者胜出，后面 dlopen 进来的 guard .so
 * 就会绑到这份实现上——相当于 Android 版的 LD_PRELOAD，但不动系统一个字节。
 * <p>
 * ★ 只在 API&lt;21 装。5.0+ 的系统 dladdr 是完整实现，我们的简化版一旦抢到符号绑定，
 * 反而会污染整个进程（其他 native 库也会绑过来）。同一个包要能同时装 4.3 的老电视
 * 和 6.0/9.0 的新电视，这个门限不能省。
 */
public class NativeCompat {

    private static final String TAG = "NATIVECOMPAT";
    private static String status = "init";

    public static void install() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            status = "skip (api " + Build.VERSION.SDK_INT + " has real dladdr)";
            Log.i(TAG, "dladdr shim " + status);
            return;
        }
        try {
            System.loadLibrary("dladdrshim");
            status = "loaded";
        } catch (Throwable t) {
            status = "fail: " + t;
        }
        Log.i(TAG, "dladdr shim " + status);
    }

    public static String getStatus() {
        return status;
    }
}
