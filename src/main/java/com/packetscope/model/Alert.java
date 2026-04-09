package com.packetscope.model;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Represents a security or policy alert raised by the PacketScope engine.
 */
public class Alert {

    public enum Severity { INFO, WARNING, CRITICAL }

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    public final Severity severity;
    public final String title;
    public final String message;
    public final String srcIp;
    public final AppType appType;
    public final Instant timestamp;

    public Alert(Severity severity, String title, String message, String srcIp, AppType appType) {
        this.severity = severity;
        this.title = title;
        this.message = message;
        this.srcIp = srcIp;
        this.appType = appType;
        this.timestamp = Instant.now();
    }

    public String formattedTime() {
        return FMT.format(timestamp);
    }

    public String severityIcon() {
        return switch (severity) {
            case INFO     -> "ℹ️";
            case WARNING  -> "⚠️";
            case CRITICAL -> "🚨";
        };
    }

    @Override
    public String toString() {
        return String.format("[%s] %s %s — %s (%s)", formattedTime(), severityIcon(), title, message, srcIp);
    }
}
