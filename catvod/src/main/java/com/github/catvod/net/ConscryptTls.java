package com.github.catvod.net;

import android.os.Build;
import android.util.Log;

import org.conscrypt.Conscrypt;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Provider;
import java.security.Security;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.ConnectionSpec;

/**
 * Android 4.3 / API18 的 TLS 兜底栈。
 * <p>
 * 系统自带的 JSSE（Harmony + OpenSSL 1.0.1e）编译期就裁掉了 AES-GCM 与 SHA256/SHA384 的 PRF，
 * 导致「只提供 GCM 套件」的站点（如 ss1.eisite.cn）在本机握手必失败：
 * API18 实测 54 个套件里 GCM=0、新 PRF 的 CBC 也是 0，交集为空。
 * <p>
 * 这里换成 Conscrypt 1.4.2（BoringSSL + 自带 libconscrypt_jni.so），在 API18 上实测可用：
 * 提供 8 个 GCM 套件、13 个 ECDHE 套件，默认启用的 15 个里同时含
 * ECDHE-*-GCM、RSA-*-GCM、CHACHA20 与老式 CBC，足够应付各种服务端。
 * <p>
 * 只替换本应用自己的 SSLContext，不动系统 Provider 顺序（避免影响其它库）。
 */
public class ConscryptTls extends SSLSocketFactory {

    public static final String TAG = "TLSSTACK";
    /** API 低于此值时系统 TLS 栈不可用（4.3 及以下）。 */
    public static final int MIN_API = Build.VERSION_CODES.KITKAT;

    /**
     * 交给 OkHttp 用的 ConnectionSpec。
     * 必须放开 OkHttp 自己的白名单：MODERN_TLS 只认 ECDHE 系套件，而 ss1.eisite.cn 这类站只给
     * TLS_RSA_WITH_AES_256_GCM_SHA384 —— OkHttp 的 apply() 会把 socket 的套件重写成它的白名单，
     * 不放开就会重蹈系统栈的覆辙。
     */
    public static final ConnectionSpec OKHTTP_SPEC = new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .allEnabledCipherSuites()
            .allEnabledTlsVersions()
            .build();

    private static Provider provider;
    private static String status = "uninitialized";
    private static boolean available;
    private static boolean defaultInstalled;

    static {
        try {
            provider = Conscrypt.newProvider();
            Provider installed = Security.getProvider(provider.getName());
            if (installed == null) Security.addProvider(provider);
            else provider = installed;
            available = true;
            status = "conscrypt " + provider.getVersion() + " ready";
        } catch (Throwable t) {
            available = false;
            status = "conscrypt unavailable: " + t;
            Log.e(TAG, status, t);
        }
    }

    private final SSLSocketFactory delegate;

    public ConscryptTls() {
        this(SSLCompat.TM);
    }

    public ConscryptTls(X509TrustManager tm) {
        SSLSocketFactory factory = null;
        if (available) {
            try {
                SSLContext context = SSLContext.getInstance("TLSv1.2", provider);
                context.init(null, new TrustManager[]{tm}, null);
                factory = context.getSocketFactory();
                /*
                 * ★ 两个坑，都是实测撞出来的，别"顺手优化"：
                 *
                 * 1. 不要 setEnabledCipherSuites(factory.getSupportedCipherSuites())。
                 *    supported 里混着 TLS1.3 的 TLS_AES_*_GCM_* 条目，全塞进 enabled 后
                 *    BoringSSL 会走 TLS1.3 的 ClientHello 路径，CDN 回
                 *    TLSV1_ALERT_INAPPROPRIATE_FALLBACK，握手直接失败（实测 92ms 挂）。
                 *
                 * 2. 不要 setEnabledProtocols(["TLSv1.2","TLSv1.1","TLSv1"]) 去"兼容老站"。
                 *    同理会让 ClientHello 与自报的 max 版本不一致，也可能被判 fallback。
                 *
                 * 结论：协议和套件一律用 Conscrypt 自己的默认值（min 1.0 / max 1.2，
                 * 15 个套件，已含 ECDHE-GCM / RSA-GCM / CHACHA20 / CBC），
                 * 由 OkHttp 的 ConnectionSpec 侧放开白名单即可（见 OKHTTP_SPEC）。
                 */
            } catch (Throwable t) {
                status = "context init failed: " + t;
                Log.e(TAG, status, t);
                factory = null;
            }
        }
        this.delegate = factory;
        Log.i(TAG, "ConscryptTls created, delegate=" + (delegate == null ? "null" : delegate.getClass().getSimpleName())
                + " suites=" + (delegate == null ? 0 : delegate.getDefaultCipherSuites().length));
    }

    public boolean isUsable() {
        return delegate != null;
    }

    /** 由已安装的 Conscrypt 栈构造；不可用则返回 null，调用方可退回系统栈。 */
    public static ConscryptTls create() {
        ConscryptTls tls = new ConscryptTls();
        return tls.isUsable() ? tls : null;
    }

    public static String status() {
        return status;
    }

    public static boolean isAvailable() {
        return available;
    }

    /**
     * 把 HttpsURLConnection 的默认工厂也切到 Conscrypt。
     * TBS/WebView 与其它进程不受影响；本进程内用 HttpURLConnection 的第三方爬虫 jar 会受益。
     */
    public static void installDefault() {
        if (defaultInstalled) return;
        ConscryptTls tls = create();
        if (tls == null) return;
        try {
            HttpsURLConnection.setDefaultSSLSocketFactory(tls);
            defaultInstalled = true;
            Log.i(TAG, "HttpsURLConnection default factory -> conscrypt");
        } catch (Throwable t) {
            Log.w(TAG, "installDefault failed: " + t);
        }
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return delegate.createSocket(s, host, port, autoClose);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return delegate.createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return delegate.createSocket(host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return delegate.createSocket(address, port, localAddress, localPort);
    }

}
