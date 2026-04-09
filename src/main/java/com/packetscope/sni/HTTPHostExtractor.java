package com.packetscope.sni;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the Host header from plain HTTP requests.
 * Used when traffic is on port 80 (HTTP) rather than 443 (HTTPS).
 *
 * HTTP request starts with: GET /path HTTP/1.1\r\nHost: example.com\r\n
 */
public class HTTPHostExtractor {

    private static final String[] HTTP_METHODS = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "
    };

    public static Optional<String> extract(byte[] payload) {
        if (payload == null || payload.length < 10) return Optional.empty();

        String text;
        try {
            text = new String(payload, 0, Math.min(payload.length, 2048), StandardCharsets.US_ASCII);
        } catch (Exception e) {
            return Optional.empty();
        }

        // Verify it's an HTTP request
        boolean isHttp = false;
        for (String method : HTTP_METHODS) {
            if (text.startsWith(method)) { isHttp = true; break; }
        }
        if (!isHttp) return Optional.empty();

        // Find the Host header (case-insensitive search)
        String lower = text.toLowerCase();
        int hostIdx = lower.indexOf("\r\nhost: ");
        if (hostIdx == -1) hostIdx = lower.indexOf("\nhost: ");

        if (hostIdx == -1) return Optional.empty();

        int valueStart = text.indexOf(':', hostIdx + 2) + 2; // Skip "Host: "
        int valueEnd   = text.indexOf('\r', valueStart);
        if (valueEnd == -1) valueEnd = text.indexOf('\n', valueStart);
        if (valueEnd == -1) return Optional.empty();

        String host = text.substring(valueStart, valueEnd).trim().toLowerCase();

        // Strip port if present (e.g., "example.com:8080")
        int colonIdx = host.indexOf(':');
        if (colonIdx != -1) host = host.substring(0, colonIdx);

        return host.isEmpty() ? Optional.empty() : Optional.of(host);
    }
}
