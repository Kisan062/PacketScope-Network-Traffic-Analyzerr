package com.packetscope.parser;

import com.packetscope.model.FiveTuple;
import com.packetscope.model.PacketInfo;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Parses raw Ethernet frame bytes into a structured PacketInfo.
 *
 * Packet structure (nested like Russian dolls):
 *  [Ethernet 14B] → [IPv4 20B+] → [TCP 20B+ | UDP 8B] → [Payload]
 */
public class PacketParser {

    private static final int ETHERTYPE_IPV4 = 0x0800;
    private static final int PROTO_TCP = 6;
    private static final int PROTO_UDP = 17;

    /**
     * Parse a raw packet. Returns null if the packet is malformed or unsupported.
     */
    public static PacketInfo parse(byte[] raw) {
        if (raw == null || raw.length < 34) return null; // Too short

        ByteBuffer buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);

        // ── Ethernet Header (14 bytes) ────────────────────────────
        buf.position(12);
        int etherType = Short.toUnsignedInt(buf.getShort()); // bytes 12-13
        if (etherType != ETHERTYPE_IPV4) return null;        // Only IPv4 for now

        // ── IPv4 Header ───────────────────────────────────────────
        int ipStart = 14;
        if (raw.length < ipStart + 20) return null;

        int ihl        = (raw[ipStart] & 0x0F) * 4;         // Header length in bytes
        int protocol   = Byte.toUnsignedInt(raw[ipStart + 9]);
        int totalLen   = Short.toUnsignedInt(buf.getShort(ipStart + 2));

        String srcIp = formatIp(raw, ipStart + 12);
        String dstIp = formatIp(raw, ipStart + 16);

        int transportStart = ipStart + ihl;
        if (raw.length < transportStart + 4) return null;

        // ── TCP / UDP ─────────────────────────────────────────────
        int srcPort, dstPort;
        boolean hasTcp = false, hasUdp = false;
        boolean isSyn = false, isFin = false, isRst = false;
        int payloadStart;

        if (protocol == PROTO_TCP) {
            if (raw.length < transportStart + 20) return null;
            srcPort = Short.toUnsignedInt(buf.getShort(transportStart));
            dstPort = Short.toUnsignedInt(buf.getShort(transportStart + 2));
            int dataOffset = ((raw[transportStart + 12] & 0xF0) >> 4) * 4;
            int flags      = Byte.toUnsignedInt(raw[transportStart + 13]);
            isSyn = (flags & 0x02) != 0;
            isFin = (flags & 0x01) != 0;
            isRst = (flags & 0x04) != 0;
            hasTcp = true;
            payloadStart = transportStart + dataOffset;

        } else if (protocol == PROTO_UDP) {
            if (raw.length < transportStart + 8) return null;
            srcPort = Short.toUnsignedInt(buf.getShort(transportStart));
            dstPort = Short.toUnsignedInt(buf.getShort(transportStart + 2));
            hasUdp = true;
            payloadStart = transportStart + 8;

        } else {
            return null; // Unsupported protocol
        }

        // ── Payload ───────────────────────────────────────────────
        byte[] payload;
        if (payloadStart < raw.length) {
            int payloadLen = raw.length - payloadStart;
            payload = new byte[payloadLen];
            System.arraycopy(raw, payloadStart, payload, 0, payloadLen);
        } else {
            payload = new byte[0];
        }

        FiveTuple tuple = new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);
        return new PacketInfo(tuple, payload, totalLen, hasTcp, hasUdp, isSyn, isFin, isRst, raw);
    }

    /** Format 4 raw bytes as "a.b.c.d" */
    private static String formatIp(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "." +
               (data[offset+1] & 0xFF) + "." +
               (data[offset+2] & 0xFF) + "." +
               (data[offset+3] & 0xFF);
    }
}
