package tv.danmaku.ijk.media.player;

import android.net.Uri;

import java.util.Map;

public class MediaSource {

    private final Map<String, String> headers;
    private final Uri uri;
    /**
     * 直播标记。由上层判定后传入：直播要开 {@code infbuf/packet-buffering=0/framedrop=5}
     * 这组「丢帧不停顿」策略（酷9 直播在同类硬件上实测有效），点播绝不能开——seek 会跳帧。
     * URL 兜底判定（rtsp/rtmp/udp/rtp/.flv）放在 IjkVideoView 里，两处取或。
     */
    private final boolean live;

    public MediaSource(Map<String, String> headers, Uri uri) {
        this(headers, uri, false);
    }

    public MediaSource(Map<String, String> headers, Uri uri, boolean live) {
        this.headers = headers;
        this.uri = uri;
        this.live = live;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public Uri getUri() {
        return uri;
    }

    public boolean isLive() {
        return live;
    }
}
