package com.dpianalyzer.sni;

import com.dpianalyzer.model.AppType;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Maps a domain name (SNI or HTTP Host) to an AppType.
 * Uses substring matching with ordered rules — first match wins.
 */
public class AppClassifier {

    // Ordered: more specific patterns before general ones
    private static final Map<String, AppType> RULES = new LinkedHashMap<>();

    static {
        // Video streaming
        RULES.put("youtube",     AppType.YOUTUBE);
        RULES.put("youtu.be",    AppType.YOUTUBE);
        RULES.put("googlevideo", AppType.YOUTUBE);
        RULES.put("netflix",     AppType.NETFLIX);
        RULES.put("nflxvideo",   AppType.NETFLIX);
        RULES.put("tiktok",      AppType.TIKTOK);
        RULES.put("bytedance",   AppType.TIKTOK);
        RULES.put("zoom",        AppType.ZOOM);

        // Social media
        RULES.put("facebook",    AppType.FACEBOOK);
        RULES.put("fbcdn",       AppType.FACEBOOK);
        RULES.put("instagram",   AppType.INSTAGRAM);
        RULES.put("cdninstagram",AppType.INSTAGRAM);
        RULES.put("twitter",     AppType.TWITTER);
        RULES.put("twimg",       AppType.TWITTER);
        RULES.put("t.co",        AppType.TWITTER);
        RULES.put("discord",     AppType.DISCORD);

        // Messaging
        RULES.put("whatsapp",    AppType.WHATSAPP);
        RULES.put("wa.me",       AppType.WHATSAPP);
        RULES.put("telegram",    AppType.TELEGRAM);

        // Tech giants
        RULES.put("google",      AppType.GOOGLE);
        RULES.put("googleapis",  AppType.GOOGLE);
        RULES.put("gstatic",     AppType.GOOGLE);
        RULES.put("github",      AppType.GITHUB);
        RULES.put("amazon",      AppType.AMAZON);
        RULES.put("amazonaws",   AppType.AMAZON);
        RULES.put("microsoft",   AppType.MICROSOFT);
        RULES.put("azure",       AppType.MICROSOFT);
        RULES.put("apple",       AppType.APPLE);
        RULES.put("icloud",      AppType.APPLE);
        RULES.put("cloudflare",  AppType.CLOUDFLARE);
    }

    /**
     * Classify by SNI/hostname. Returns UNKNOWN if no pattern matches.
     */
    public static AppType classify(String hostname) {
        if (hostname == null || hostname.isBlank()) return AppType.UNKNOWN;
        String lower = hostname.toLowerCase();
        for (Map.Entry<String, AppType> entry : RULES.entrySet()) {
            if (lower.contains(entry.getKey())) return entry.getValue();
        }
        return AppType.UNKNOWN;
    }

    /**
     * Classify by port number alone (fallback when no SNI available).
     */
    public static AppType classifyByPort(int dstPort) {
        return switch (dstPort) {
            case 80  -> AppType.HTTP;
            case 443 -> AppType.HTTPS;
            case 53  -> AppType.DNS;
            default  -> AppType.UNKNOWN;
        };
    }
}
