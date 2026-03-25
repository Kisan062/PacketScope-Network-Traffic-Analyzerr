package com.dpianalyzer.sni;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts Server Name Indication (SNI) from TLS Client Hello packets.
 *
 * TLS Client Hello structure:
 *   Byte 0:     Content Type = 0x16 (Handshake)
 *   Bytes 1-2:  Version
 *   Bytes 3-4:  Record Length
 *   Byte 5:     Handshake Type = 0x01 (Client Hello)
 *   ...extensions → SNI Extension (type 0x0000)
 *
 * Even though HTTPS is encrypted, the domain name in the
 * Client Hello is still visible in plaintext!
 */
public class SNIExtractor {

    private static final int TLS_HANDSHAKE      = 0x16;
    private static final int TLS_CLIENT_HELLO   = 0x01;
    private static final int EXT_SNI            = 0x0000;
    private static final int SNI_TYPE_HOSTNAME  = 0x00;

    /**
     * Attempt to extract the SNI hostname from a TLS payload.
     * Returns empty if this is not a TLS Client Hello or SNI is absent.
     */
    public static Optional<String> extract(byte[] payload) {
        if (payload == null || payload.length < 43) return Optional.empty();

        // Check Content Type = Handshake (0x16)
        if ((payload[0] & 0xFF) != TLS_HANDSHAKE) return Optional.empty();

        // Check Handshake Type = Client Hello (0x01) at byte 5
        if ((payload[5] & 0xFF) != TLS_CLIENT_HELLO) return Optional.empty();

        try {
            int offset = 43; // Start after fixed Client Hello fields

            // Skip Session ID
            if (offset >= payload.length) return Optional.empty();
            int sessionIdLen = payload[offset] & 0xFF;
            offset += 1 + sessionIdLen;

            // Skip Cipher Suites
            if (offset + 2 > payload.length) return Optional.empty();
            int cipherLen = readUint16(payload, offset);
            offset += 2 + cipherLen;

            // Skip Compression Methods
            if (offset + 1 > payload.length) return Optional.empty();
            int compLen = payload[offset] & 0xFF;
            offset += 1 + compLen;

            // Extensions
            if (offset + 2 > payload.length) return Optional.empty();
            int extTotalLen = readUint16(payload, offset);
            offset += 2;

            int extEnd = offset + extTotalLen;

            while (offset + 4 <= extEnd && offset + 4 <= payload.length) {
                int extType = readUint16(payload, offset);
                int extLen  = readUint16(payload, offset + 2);
                offset += 4;

                if (extType == EXT_SNI) {
                    // SNI list length (2 bytes), then entries
                    if (offset + 5 > payload.length) return Optional.empty();
                    // offset+0: SNI list len, offset+2: SNI type, offset+3: SNI name len
                    int sniType    = payload[offset + 2] & 0xFF;
                    int sniNameLen = readUint16(payload, offset + 3);
                    if (sniType == SNI_TYPE_HOSTNAME && offset + 5 + sniNameLen <= payload.length) {
                        String sni = new String(payload, offset + 5, sniNameLen, StandardCharsets.US_ASCII);
                        return Optional.of(sni.toLowerCase().trim());
                    }
                    return Optional.empty();
                }

                offset += extLen;
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            // Malformed packet — silently ignore
        }

        return Optional.empty();
    }

    /** Read 2 bytes as unsigned big-endian int */
    private static int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
