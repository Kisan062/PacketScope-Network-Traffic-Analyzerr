package com.packetscope.model;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Represents a tracked network flow (connection).
 * Thread-safe for multi-threaded packet processing.
 */
public class Flow {

    public final FiveTuple tuple;

    public volatile AppType appType = AppType.UNKNOWN;
    public volatile String sni = "";         // Extracted domain from TLS/HTTP
    public volatile boolean blocked = false;
    public volatile String blockReason = "";

    private final AtomicLong packetCount = new AtomicLong(0);
    private final AtomicLong byteCount = new AtomicLong(0);

    public final Instant startTime;
    public volatile Instant lastSeen;

    // Alert flag — set true when an alert has been raised for this flow
    public volatile boolean alerted = false;

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
        this.startTime = Instant.now();
        this.lastSeen = startTime;
    }

    public void recordPacket(int bytes) {
        packetCount.incrementAndGet();
        byteCount.addAndGet(bytes);
        lastSeen = Instant.now();
    }

    public long getPacketCount() { return packetCount.get(); }
    public long getByteCount()   { return byteCount.get(); }

    public long durationMs() {
        return lastSeen.toEpochMilli() - startTime.toEpochMilli();
    }

    @Override
    public String toString() {
        return String.format("[Flow] %s | App=%s | SNI=%s | Pkts=%d | Bytes=%d | Blocked=%s",
                tuple, appType.displayName, sni, getPacketCount(), getByteCount(), blocked);
    }
}
