package com.fongmi.android.tv.player;

import android.net.Uri;

import com.fongmi.android.tv.Setting;
import com.fongmi.android.tv.bean.Channel;
import com.fongmi.android.tv.bean.Result;
import com.fongmi.android.tv.player.exo.ExoUtil;
import com.fongmi.android.tv.utils.UrlUtil;

import java.util.Map;

import tv.danmaku.ijk.media.player.MediaSource;
import tv.danmaku.ijk.media.player.ui.IjkVideoView;

public class IjkUtil {

    public static MediaSource getSource(Result result) {
        return getSource(result.getHeaders(), result.getRealUrl(), false);
    }

    public static MediaSource getSource(Channel channel) {
        // 直播模块：把「这是直播」显式带给 ijk，走 infbuf/丢帧那组参数（酷9 实测有效的策略）
        return getSource(channel.getHeaders(), channel.getUrl(), true);
    }

    public static MediaSource getSource(Map<String, String> headers, String url) {
        return getSource(headers, url, false);
    }

    public static MediaSource getSource(Map<String, String> headers, String url, boolean live) {
        Uri uri = UrlUtil.uri(url);
        return new MediaSource(Players.checkUa(headers), uri, live);
    }

    public static void setSubtitleView(IjkVideoView ijk) {
        ijk.getSubtitleView().setStyle(ExoUtil.getCaptionStyle());
        ijk.getSubtitleView().setApplyEmbeddedFontSizes(false);
        ijk.getSubtitleView().setApplyEmbeddedStyles(!Setting.isCaption());
        if (Setting.getSubtitleTextSize() != 0) ijk.getSubtitleView().setFractionalTextSize(Setting.getSubtitleTextSize());
        if (Setting.getSubtitleBottomPadding() != 0) ijk.getSubtitleView().setBottomPaddingFraction(Setting.getSubtitleBottomPadding());
    }
}
