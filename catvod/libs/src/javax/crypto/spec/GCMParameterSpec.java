package javax.crypto.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * API 19 才有的 javax.crypto.spec.GCMParameterSpec 的 4.x 兼容垫片。
 * <p>
 * 关键设计：**继承 IvParameterSpec**。Android 4.3 的 BC 里没有 GCM 专用的参数类型，
 * 只认 IvParameterSpec（tag 长度固定按 128 处理，tag 跟在密文后面）。
 * 让它成为 IvParameterSpec 的子类，同一个对象既能喂给老 BC，也能被新版
 * Conscrypt/BoringSSL 的 OpenSSLCipher 用 instanceof 认出来，两代栈共用一份参数。
 * <p>
 * 与官方实现的差别只有一处：官方版直接持有 iv 的拷贝，这里复用父类字段。
 * getIV() / getTLen() 语义保持一致。
 */
public class GCMParameterSpec extends IvParameterSpec implements AlgorithmParameterSpec {

    private final int tLen;

    public GCMParameterSpec(int tLen, byte[] src) {
        this(tLen, src, 0, src == null ? 0 : src.length);
    }

    public GCMParameterSpec(int tLen, byte[] src, int offset, int len) {
        super(src, offset, len);
        if (tLen < 0) throw new IllegalArgumentException("tLen < 0");
        this.tLen = tLen;
    }

    public int getTLen() {
        return tLen;
    }
}
