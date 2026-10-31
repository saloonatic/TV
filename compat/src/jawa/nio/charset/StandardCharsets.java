package jawa.nio.charset;

import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;

/**
 * Android 4.x (API<19) 缺失 java.nio.charset.StandardCharsets 的兼容实现。
 * 编译后字节码中的 jawa/ 会被替换为 java/（等长改名），从而成为
 * java.nio.charset.StandardCharsets，供 API 18 上的第三方爬虫 jar 解析。
 * API>=19 的设备上 boot classpath 已有该类，本实现不会被使用。
 */
public final class StandardCharsets {

    public static final Charset US_ASCII = charset("US-ASCII");
    public static final Charset ISO_8859_1 = charset("ISO-8859-1");
    public static final Charset UTF_8 = charset("UTF-8");
    public static final Charset UTF_16BE = charset("UTF-16BE");
    public static final Charset UTF_16LE = charset("UTF-16LE");
    public static final Charset UTF_16 = charset("UTF-16");

    private StandardCharsets() {
    }

    private static Charset charset(String name) {
        try {
            return Charset.forName(name);
        } catch (UnsupportedCharsetException e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
