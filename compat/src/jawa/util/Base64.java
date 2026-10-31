package jawa.util;

/**
 * Android 4.x 缺失 java.util.Base64（API 26 才有）的兼容实现。
 * 纯 Java 实现，不依赖 android.util.Base64，便于用普通 javac 编译。
 * 编译后字节码中的 jawa/ 会被替换成 java/（等长），成为 java.util.Base64。
 *
 * 覆盖常用子集：basic / url-safe / mime 的 Encoder、Decoder，
 * encode/encodeToString/decode(String)/decode(byte[])/withoutPadding。
 */
public class Base64 {

    private static final char[] STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
    private static final char[] URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".toCharArray();

    private static final Encoder STD_ENCODER = new Encoder(STD, true, false);
    private static final Encoder URL_ENCODER = new Encoder(URL, true, false);
    private static final Encoder MIME_ENCODER = new Encoder(STD, true, true);
    private static final Decoder STD_DECODER = new Decoder(STD, false);
    private static final Decoder URL_DECODER = new Decoder(URL, false);
    private static final Decoder MIME_DECODER = new Decoder(STD, true);

    private Base64() {
    }

    public static Encoder getEncoder() {
        return STD_ENCODER;
    }

    public static Encoder getUrlEncoder() {
        return URL_ENCODER;
    }

    public static Encoder getMimeEncoder() {
        return MIME_ENCODER;
    }

    public static Encoder getMimeEncoder(int lineLength, byte[] lineSeparator) {
        return MIME_ENCODER;
    }

    public static Decoder getDecoder() {
        return STD_DECODER;
    }

    public static Decoder getUrlDecoder() {
        return URL_DECODER;
    }

    public static Decoder getMimeDecoder() {
        return MIME_DECODER;
    }

    public static class Encoder {

        private final char[] alphabet;
        private final boolean padding;
        private final boolean mime;

        Encoder(char[] alphabet, boolean padding, boolean mime) {
            this.alphabet = alphabet;
            this.padding = padding;
            this.mime = mime;
        }

        public Encoder withoutPadding() {
            return new Encoder(alphabet, false, mime);
        }

        public String encodeToString(byte[] src) {
            return new String(encode(src));
        }

        public byte[] encode(byte[] src) {
            if (src == null) throw new NullPointerException();
            int len = src.length;
            StringBuilder sb = new StringBuilder(((len + 2) / 3) * 4 + (mime ? len / 57 + 2 : 0));
            int line = 0;
            for (int i = 0; i < len; i += 3) {
                int b0 = src[i] & 0xff;
                int b1 = i + 1 < len ? src[i + 1] & 0xff : -1;
                int b2 = i + 2 < len ? src[i + 2] & 0xff : -1;
                sb.append(alphabet[b0 >>> 2]);
                sb.append(alphabet[((b0 & 0x03) << 4) | (b1 < 0 ? 0 : b1 >>> 4)]);
                if (b1 < 0) {
                    if (padding) {
                        sb.append('=');
                        sb.append('=');
                    }
                } else {
                    sb.append(alphabet[((b1 & 0x0f) << 2) | (b2 < 0 ? 0 : b2 >>> 6)]);
                    if (b2 < 0) {
                        if (padding) sb.append('=');
                    } else {
                        sb.append(alphabet[b2 & 0x3f]);
                    }
                }
                line += 4;
                if (mime && line >= 76) {
                    sb.append("\r\n");
                    line = 0;
                }
            }
            return sb.toString().getBytes(java.nio.charset.Charset.forName("ISO-8859-1"));
        }

        public int encode(byte[] src, byte[] dst) {
            byte[] out = encode(src);
            int n = Math.min(out.length, dst.length);
            System.arraycopy(out, 0, dst, 0, n);
            return n;
        }
    }

    public static class Decoder {

        private final int[] table = new int[256];
        private final boolean mime;

        Decoder(char[] alphabet, boolean mime) {
            this.mime = mime;
            for (int i = 0; i < table.length; i++) table[i] = -1;
            for (int i = 0; i < alphabet.length; i++) table[alphabet[i]] = i;
            // URL 与标准字母表的 '-' '_' 互认，避免同一份数据两种编码互不兼容
            if (alphabet == STD) {
                table['-'] = 62;
                table['_'] = 63;
            } else {
                table['+'] = 62;
                table['/'] = 63;
            }
        }

        public byte[] decode(String src) {
            if (src == null) throw new NullPointerException();
            return decodeInternal(src.toCharArray());
        }

        public byte[] decode(byte[] src) {
            if (src == null) throw new NullPointerException();
            char[] chars = new char[src.length];
            for (int i = 0; i < src.length; i++) chars[i] = (char) (src[i] & 0xff);
            return decodeInternal(chars);
        }

        private byte[] decodeInternal(char[] in) {
            byte[] out = new byte[in.length * 3 / 4 + 3];
            int outPos = 0;
            int buffer = 0;
            int bits = 0;
            int pad = 0;
            for (char c : in) {
                if (c == '=') {
                    pad++;
                    continue;
                }
                if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
                    if (mime) continue;
                    continue;
                }
                int v = c < 256 ? table[c] : -1;
                if (v < 0) throw new IllegalArgumentException("Illegal base64 character " + Integer.toString(c, 16));
                buffer = (buffer << 6) | v;
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    out[outPos++] = (byte) (buffer >>> bits);
                    buffer &= (1 << bits) - 1;
                }
            }
            byte[] result = new byte[outPos];
            System.arraycopy(out, 0, result, 0, outPos);
            return result;
        }
    }
}
