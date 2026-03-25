package com.dpianalyzer.model;

/**
 * Application-level traffic classification.
 * Mapped from SNI hostnames or port patterns.
 */
public enum AppType {
    UNKNOWN("Unknown", "❓"),
    HTTP("HTTP", "🌐"),
    HTTPS("HTTPS", "🔒"),
    DNS("DNS", "📡"),
    YOUTUBE("YouTube", "▶️"),
    FACEBOOK("Facebook", "📘"),
    INSTAGRAM("Instagram", "📷"),
    TWITTER("Twitter/X", "🐦"),
    GOOGLE("Google", "🔍"),
    NETFLIX("Netflix", "🎬"),
    TIKTOK("TikTok", "🎵"),
    WHATSAPP("WhatsApp", "💬"),
    TELEGRAM("Telegram", "✈️"),
    GITHUB("GitHub", "🐙"),
    AMAZON("Amazon", "📦"),
    MICROSOFT("Microsoft", "🪟"),
    APPLE("Apple", "🍎"),
    CLOUDFLARE("Cloudflare", "☁️"),
    ZOOM("Zoom", "📹"),
    DISCORD("Discord", "🎮");

    public final String displayName;
    public final String emoji;

    AppType(String displayName, String emoji) {
        this.displayName = displayName;
        this.emoji = emoji;
    }

    public String label() {
        return emoji + " " + displayName;
    }
}
