package com.packetscope.model;

import java.util.Objects;

/**
 * Uniquely identifies a network connection/flow.
 * A flow is a bidirectional stream between two endpoints.
 */
public class FiveTuple {

    public final String srcIp;
    public final String dstIp;
    public final int srcPort;
    public final int dstPort;
    public final int protocol; // 6=TCP, 17=UDP

    public FiveTuple(String srcIp, String dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple t)) return false;
        return srcPort == t.srcPort && dstPort == t.dstPort && protocol == t.protocol
                && Objects.equals(srcIp, t.srcIp) && Objects.equals(dstIp, t.dstIp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        String proto = protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "PROTO:" + protocol;
        return srcIp + ":" + srcPort + " → " + dstIp + ":" + dstPort + " [" + proto + "]";
    }
}
