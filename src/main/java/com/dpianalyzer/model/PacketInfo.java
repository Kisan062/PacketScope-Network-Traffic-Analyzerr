package com.dpianalyzer.model;

import java.time.Instant;

/**
 * Parsed representation of a single network packet.
 */
public class PacketInfo {

    public final FiveTuple tuple;
    public final byte[] payload;       // Application-layer payload bytes
    public final int totalLength;      // Full packet size in bytes
    public final Instant captureTime;

    // Protocol flags
    public final boolean hasTcp;
    public final boolean hasUdp;
    public final boolean isSyn;        // TCP SYN flag
    public final boolean isFin;        // TCP FIN flag
    public final boolean isRst;        // TCP RST flag

    // Raw packet bytes (full Ethernet frame)
    public final byte[] rawData;

    public PacketInfo(FiveTuple tuple, byte[] payload, int totalLength,
                      boolean hasTcp, boolean hasUdp,
                      boolean isSyn, boolean isFin, boolean isRst,
                      byte[] rawData) {
        this.tuple = tuple;
        this.payload = payload;
        this.totalLength = totalLength;
        this.hasTcp = hasTcp;
        this.hasUdp = hasUdp;
        this.isSyn = isSyn;
        this.isFin = isFin;
        this.isRst = isRst;
        this.rawData = rawData;
        this.captureTime = Instant.now();
    }
}
