package jawa.util;

import java.util.Arrays;
import java.util.Comparator;

/**
 * Android 4.3 (API 18) 上 {@code java.util.Objects} 的替代实现。
 *
 * <p>{@code java.util.Objects} 是 <b>API 19 (4.4)</b> 才加进 libcore 的。第三方爬虫 dex 大量用它
 * （典型是 {@code Objects.requireNonNull}、Kotlin/Retrofit 生成代码里的 {@code Objects.equals}），
 * 在 4.3 上直接 {@code NoClassDefFoundError} / {@code NoSuchMethodError}。
 *
 * <p>⚠️ 源码包名故意写成 {@code jawa.util}：{@code javac} 从 JDK9 起禁止编译 {@code java.*}
 * （会报 "package exists in another module: java.base"）。
 * 构建时把 class 文件里的 "jawa" 改成同长度的 "java" 即可（见 mkcompat.sh）。
 * 运行时 App 的 PathClassLoader 会先问 BootClassLoader（没有），再落到自己的 dex，于是生效。
 */
public final class Objects {

    private Objects() {
    }

    public static boolean equals(Object a, Object b) {
        return (a == b) || (a != null && a.equals(b));
    }

    public static boolean deepEquals(Object a, Object b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        return Arrays.deepEquals(new Object[]{a}, new Object[]{b});
    }

    public static int hashCode(Object o) {
        return o != null ? o.hashCode() : 0;
    }

    public static int hash(Object... values) {
        return Arrays.hashCode(values);
    }

    public static String toString(Object o) {
        return String.valueOf(o);
    }

    public static String toString(Object o, String nullDefault) {
        return (o != null) ? o.toString() : nullDefault;
    }

    public static <T> int compare(T a, T b, Comparator<? super T> c) {
        return (a == b) ? 0 : c.compare(a, b);
    }

    public static <T> T requireNonNull(T obj) {
        if (obj == null) throw new NullPointerException();
        return obj;
    }

    public static <T> T requireNonNull(T obj, String message) {
        if (obj == null) throw new NullPointerException(message);
        return obj;
    }

    public static boolean isNull(Object obj) {
        return obj == null;
    }

    public static boolean nonNull(Object obj) {
        return obj != null;
    }
}
