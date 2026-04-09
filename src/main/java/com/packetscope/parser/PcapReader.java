package com.packetscope.parser;

import java.io.*;

/**
 * Reads Wireshark/tcpdump .pcap files.
 * Manually reads bytes to avoid any ByteBuffer byte-order confusion.
 */
public class PcapReader implements Closeable {

    private DataInputStream dis;
    private boolean bigEndian = false;
    private boolean open      = false;

    public static class RawPacket {
        public final long   tsSec;
        public final long   tsUsec;
        public final int    inclLen;
        public final int    origLen;
        public final byte[] data;

        public RawPacket(long tsSec, long tsUsec, int inclLen, int origLen, byte[] data) {
            this.tsSec   = tsSec;
            this.tsUsec  = tsUsec;
            this.inclLen = inclLen;
            this.origLen = origLen;
            this.data    = data;
        }
    }

    public void open(String filePath) throws IOException {
        dis = new DataInputStream(
                new BufferedInputStream(new FileInputStream(filePath)));

        // Read magic number as 4 raw bytes — no ByteBuffer involved
        int b0 = dis.read();
        int b1 = dis.read();
        int b2 = dis.read();
        int b3 = dis.read();
        if (b0 < 0) throw new IOException("Empty file");

        // Little-endian magic: bytes on disk = D4 C3 B2 A1
        // Big-endian magic:    bytes on disk = A1 B2 C3 D4
        if      (b0==0xD4 && b1==0xC3 && b2==0xB2 && b3==0xA1) bigEndian = false;
        else if (b0==0xA1 && b1==0xB2 && b2==0xC3 && b3==0xD4) bigEndian = true;
        else throw new IOException(String.format(
                "Not a valid PCAP file. Magic bytes: %02X %02X %02X %02X",
                b0, b1, b2, b3));

        System.out.println("[PcapReader] byteOrder=" + (bigEndian ? "BIG" : "LITTLE"));

        // Skip remaining 20 bytes of global header:
        // version_major(2) + version_minor(2) + thiszone(4)
        // + sigfigs(4) + snaplen(4) + network(4) = 20 bytes
        skipFully(20);
        open = true;
    }

    public RawPacket readNextPacket() throws IOException {
        if (!open) throw new IllegalStateException("PcapReader not open");

        // Read 16-byte packet record header
        byte[] hdr = new byte[16];
        int got = 0;
        while (got < 16) {
            int n = dis.read(hdr, got, 16 - got);
            if (n < 0) return null; // Clean EOF
            got += n;
        }

        long tsSec   = readU32(hdr, 0);
        long tsUsec  = readU32(hdr, 4);
        long inclLong = readU32(hdr, 8);
        long origLong = readU32(hdr, 12);

        int inclLen = (int) inclLong;

        // Sanity check
        if (inclLen <= 0 || inclLen > 65535) {
            System.err.println("[PcapReader] Invalid inclLen=" + inclLen
                    + " hex=" + Long.toHexString(inclLong) + " — EOF");
            return null;
        }

        byte[] data = new byte[inclLen];
        dis.readFully(data);
        return new RawPacket(tsSec, tsUsec, inclLen, (int) origLong, data);
    }

    /** Read 4 bytes as unsigned 32-bit, respecting detected byte order */
    private long readU32(byte[] buf, int off) {
        long b0 = buf[off]   & 0xFFL;
        long b1 = buf[off+1] & 0xFFL;
        long b2 = buf[off+2] & 0xFFL;
        long b3 = buf[off+3] & 0xFFL;
        if (bigEndian)
            return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
        else
            return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
    }

    private void skipFully(int n) throws IOException {
        int remaining = n;
        while (remaining > 0) {
            int skipped = (int) dis.skip(remaining);
            if (skipped <= 0) throw new IOException("Truncated PCAP global header");
            remaining -= skipped;
        }
    }

    @Override
    public void close() throws IOException {
        open = false;
        if (dis != null) dis.close();
    }
}
