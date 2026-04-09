package com.packetscope.util;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Random;

/**
 * Generates synthetic .pcap files for testing the PacketScope engine.
 * Writes strict little-endian PCAP format (magic = D4 C3 B2 A1).
 */
public class PcapGenerator {

    private static final Random RNG = new Random(42);

    private static final String[] SRC_IPS = {
        "192.168.1.10", "192.168.1.20", "192.168.1.50", "10.0.0.5"
    };
    private static final String[] DST_IPS = {
        "142.250.185.206", "31.13.72.36", "104.16.132.229", "8.8.8.8"
    };
    private static final String[] TLS_SNIS = {
        "www.youtube.com", "www.facebook.com", "www.google.com",
        "www.netflix.com",  "www.tiktok.com",  "api.telegram.org",
        "github.com",       "www.amazon.com",  "www.microsoft.com",
        "www.instagram.com","discord.com",      "zoom.us"
    };
    private static final String[] HTTP_HOSTS = {
        "example.com", "httpbin.org", "api.example.com", "cdn.example.net"
    };
    private static final int[] SUSP_PORTS = {3389, 445, 4444, 23};

    public static void generate(String outputPath, int packetCount) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputPath);
             BufferedOutputStream bos = new BufferedOutputStream(fos)) {

            // Write PCAP global header (24 bytes) in little-endian
            writePcapGlobalHeader(bos);

            for (int i = 0; i < packetCount; i++) {
                String src    = SRC_IPS[RNG.nextInt(SRC_IPS.length)];
                String dst    = DST_IPS[RNG.nextInt(DST_IPS.length)];
                int    srcPort = 40000 + RNG.nextInt(10000);
                int    type   = RNG.nextInt(10);

                byte[] payload;
                int    dstPort;
                boolean useTcp;

                if (type < 5) {
                    dstPort = 443;
                    useTcp  = true;
                    payload = buildTLSClientHello(TLS_SNIS[i % TLS_SNIS.length]);
                } else if (type < 7) {
                    dstPort = 80;
                    useTcp  = true;
                    payload = buildHttpRequest(HTTP_HOSTS[i % HTTP_HOSTS.length]);
                } else if (type < 9) {
                    dstPort = 53;
                    useTcp  = false;
                    dst     = "8.8.8.8";
                    payload = buildFakeDns();
                } else {
                    dstPort = SUSP_PORTS[RNG.nextInt(SUSP_PORTS.length)];
                    useTcp  = true;
                    payload = new byte[RNG.nextInt(40) + 4];
                    RNG.nextBytes(payload);
                }

                byte[] frame = buildEthernetFrame(src, dst, srcPort, dstPort, payload, useTcp);
                writePacket(bos, frame);
            }
            bos.flush();
        }
        System.out.println("[PcapGenerator] Generated " + packetCount
                + " packets -> " + outputPath);
    }

    // ── TLS Client Hello with SNI ──────────────────────────────────
    private static byte[] buildTLSClientHello(String sni) {
        byte[] sniBytes = sni.getBytes();
        int    sniLen   = sniBytes.length;

        // Build SNI extension
        ByteArrayOutputStream extBuf = new ByteArrayOutputStream();
        DataOutputStream ext = new DataOutputStream(extBuf);
        try {
            ext.writeShort(0x0000);            // Extension type: SNI
            ext.writeShort(sniLen + 5);        // Extension length
            ext.writeShort(sniLen + 3);        // SNI list length
            ext.writeByte(0x00);               // SNI type: hostname
            ext.writeShort(sniLen);            // hostname length
            ext.write(sniBytes);               // hostname bytes
        } catch (IOException ignored) {}
        byte[] extData = extBuf.toByteArray();

        // Build Client Hello body
        ByteArrayOutputStream helloBuf = new ByteArrayOutputStream();
        DataOutputStream hello = new DataOutputStream(helloBuf);
        try {
            hello.writeShort(0x0303);          // TLS 1.2
            byte[] random = new byte[32];
            RNG.nextBytes(random);
            hello.write(random);               // 32 random bytes
            hello.writeByte(0);                // session ID length = 0
            hello.writeShort(2);               // cipher suites length
            hello.writeShort(0x002F);          // TLS_RSA_WITH_AES_128_CBC_SHA
            hello.writeByte(1);                // compression methods length
            hello.writeByte(0x00);             // no compression
            hello.writeShort(extData.length);  // extensions length
            hello.write(extData);
        } catch (IOException ignored) {}
        byte[] helloBody = helloBuf.toByteArray();

        // Build TLS record
        ByteArrayOutputStream recBuf = new ByteArrayOutputStream();
        DataOutputStream rec = new DataOutputStream(recBuf);
        try {
            rec.writeByte(0x16);               // Content-Type: Handshake
            rec.writeByte(0x03);               // TLS major version
            rec.writeByte(0x01);               // TLS minor version
            rec.writeShort(helloBody.length + 4); // record length
            rec.writeByte(0x01);               // Handshake: ClientHello
            rec.writeByte(0x00);               // length high byte
            rec.writeShort(helloBody.length);  // length low 2 bytes
            rec.write(helloBody);
        } catch (IOException ignored) {}
        return recBuf.toByteArray();
    }

    private static byte[] buildHttpRequest(String host) {
        return ("GET / HTTP/1.1\r\nHost: " + host
              + "\r\nUser-Agent: PacketScope-Test/1.0\r\n\r\n").getBytes();
    }

    private static byte[] buildFakeDns() {
        return new byte[]{0x00,0x01, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00};
    }

    // ── Build full Ethernet frame ──────────────────────────────────
    private static byte[] buildEthernetFrame(
            String srcIp, String dstIp, int srcPort, int dstPort,
            byte[] payload, boolean useTcp) throws IOException {

        int transportLen = useTcp ? 20 : 8;
        int ipBodyLen    = transportLen + payload.length;
        int ipTotalLen   = 20 + ipBodyLen;
        int frameLen     = 14 + ipTotalLen;

        ByteArrayOutputStream frameBuf = new ByteArrayOutputStream(frameLen);
        DataOutputStream out = new DataOutputStream(frameBuf);

        // Ethernet header (14 bytes) — big-endian fields
        out.write(new byte[]{(byte)0xAA,(byte)0xAA,(byte)0xAA,(byte)0xAA,(byte)0xAA,(byte)0xAA}); // dst MAC
        out.write(new byte[]{(byte)0xBB,(byte)0xBB,(byte)0xBB,(byte)0xBB,(byte)0xBB,(byte)0xBB}); // src MAC
        out.writeShort(0x0800); // EtherType: IPv4

        // IPv4 header (20 bytes)
        out.writeByte(0x45);              // version=4, IHL=5
        out.writeByte(0x00);              // DSCP
        out.writeShort(ipTotalLen);       // total length
        out.writeShort(RNG.nextInt(65535) & 0xFFFF); // ID
        out.writeShort(0x4000);           // flags: don't fragment
        out.writeByte(64);                // TTL
        out.writeByte(useTcp ? 6 : 17);  // protocol
        out.writeShort(0);                // checksum (skip)
        for (String p : srcIp.split("\\.")) out.writeByte(Integer.parseInt(p));
        for (String p : dstIp.split("\\.")) out.writeByte(Integer.parseInt(p));

        if (useTcp) {
            // TCP header (20 bytes)
            out.writeShort(srcPort);
            out.writeShort(dstPort);
            out.writeInt(RNG.nextInt());  // seq
            out.writeInt(0);              // ack
            out.writeByte(0x50);          // data offset = 5*4=20
            out.writeByte(0x18);          // PSH+ACK
            out.writeShort(65535);        // window
            out.writeShort(0);            // checksum
            out.writeShort(0);            // urgent
        } else {
            // UDP header (8 bytes)
            out.writeShort(srcPort);
            out.writeShort(dstPort);
            out.writeShort(8 + payload.length);
            out.writeShort(0); // checksum
        }

        out.write(payload);
        out.flush();
        return frameBuf.toByteArray();
    }

    // ── PCAP file format writers (little-endian) ───────────────────
    private static void writePcapGlobalHeader(OutputStream out) throws IOException {
        // Magic: D4 C3 B2 A1  (little-endian indicator)
        out.write(new byte[]{(byte)0xD4,(byte)0xC3,(byte)0xB2,(byte)0xA1});
        writeU16LE(out, 2);       // version major
        writeU16LE(out, 4);       // version minor
        writeU32LE(out, 0);       // thiszone
        writeU32LE(out, 0);       // sigfigs
        writeU32LE(out, 65535);   // snaplen
        writeU32LE(out, 1);       // link type: Ethernet
    }

    private static void writePacket(OutputStream out, byte[] data) throws IOException {
        long ts = System.currentTimeMillis() / 1000L;
        writeU32LE(out, (int) ts);    // ts_sec
        writeU32LE(out, 0);           // ts_usec
        writeU32LE(out, data.length); // incl_len
        writeU32LE(out, data.length); // orig_len
        out.write(data);
    }

    private static void writeU32LE(OutputStream out, int v) throws IOException {
        out.write( v         & 0xFF);
        out.write((v >>>  8) & 0xFF);
        out.write((v >>> 16) & 0xFF);
        out.write((v >>> 24) & 0xFF);
    }

    private static void writeU16LE(OutputStream out, int v) throws IOException {
        out.write( v        & 0xFF);
        out.write((v >>> 8) & 0xFF);
    }
}
