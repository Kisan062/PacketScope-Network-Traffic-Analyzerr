package com.dpianalyzer.util;

import com.dpianalyzer.parser.PacketParser;
import com.dpianalyzer.parser.PcapReader;
import com.dpianalyzer.model.PacketInfo;

import java.io.File;

/**
 * Standalone debug test — run this to verify PCAP generation and parsing.
 * Usage: included in the jar, called from Main if --debug flag passed.
 */
public class DebugTest {

    public static void runTest() {
        System.out.println("=== DPI Debug Test ===");

        try {
            // Step 1: Generate test PCAP
            File f = File.createTempFile("dpi_debug_", ".pcap");
            System.out.println("[1] Generating PCAP: " + f.getAbsolutePath());
            PcapGenerator.generate(f.getAbsolutePath(), 20);
            System.out.println("[1] File size: " + f.length() + " bytes");

            // Step 2: Read it back
            System.out.println("[2] Reading PCAP...");
            PcapReader reader = new PcapReader();
            reader.open(f.getAbsolutePath());

            int count = 0;
            int parsed = 0;
            PcapReader.RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                count++;
                System.out.println("  Packet #" + count
                        + " inclLen=" + raw.inclLen
                        + " dataLen=" + raw.data.length);

                // Step 3: Parse each packet
                PacketInfo pkt = PacketParser.parse(raw.data);
                if (pkt != null) {
                    parsed++;
                    System.out.println("    -> Parsed OK: "
                            + pkt.tuple.srcIp + ":" + pkt.tuple.srcPort
                            + " -> " + pkt.tuple.dstIp + ":" + pkt.tuple.dstPort
                            + " payload=" + pkt.payload.length + "B");
                } else {
                    System.out.println("    -> Parse FAILED (null)");
                    // Print first 20 bytes as hex
                    StringBuilder hex = new StringBuilder("    -> Raw hex: ");
                    for (int i = 0; i < Math.min(20, raw.data.length); i++) {
                        hex.append(String.format("%02X ", raw.data[i]));
                    }
                    System.out.println(hex);
                }
            }
            reader.close();

            System.out.println("[3] Total raw packets read : " + count);
            System.out.println("[3] Successfully parsed     : " + parsed);

            if (count == 0) {
                System.out.println("[!] ERROR: 0 packets read — PCAP header problem");
            } else if (parsed == 0) {
                System.out.println("[!] ERROR: packets read but none parsed — Ethernet/IP problem");
            } else {
                System.out.println("[OK] Pipeline working correctly!");
            }

        } catch (Exception e) {
            System.err.println("[!] Exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
