package com.packetscope.alerts;

import com.packetscope.model.Alert;
import com.packetscope.model.Alert.Severity;
import com.packetscope.model.AppType;
import com.packetscope.model.Flow;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Real-time alert engine for PacketScope.
 *
 * Unique features beyond basic DPI:
 *  - Threshold-based alerts (e.g., high packet rate from one IP)
 *  - Suspicious port detection
 *  - Blocked app/domain alerts with severity levels
 *  - Listener callbacks → live GUI notifications
 */
public class AlertEngine {

    // Thresholds (configurable)
    public int highPacketRateThreshold = 500;   // packets per flow before WARNING
    public int criticalPacketRateThreshold = 2000;
    public long highByteThreshold = 10 * 1024 * 1024; // 10 MB per flow

    // Known suspicious ports (not exhaustive — educational)
    private static final Set<Integer> SUSPICIOUS_PORTS = Set.of(
        23,    // Telnet (unencrypted)
        445,   // SMB (ransomware vector)
        1433,  // MSSQL
        3389,  // RDP
        4444,  // Metasploit default
        6667,  // IRC (often used by botnets)
        8080,  // Alt HTTP (often used by proxies)
        9001   // Tor
    );

    private final List<Alert> alertLog = new CopyOnWriteArrayList<>();
    private final List<Consumer<Alert>> listeners = new CopyOnWriteArrayList<>();

    /** Register a callback to receive alerts in real-time (e.g., GUI panel). */
    public void addListener(Consumer<Alert> listener) {
        listeners.add(listener);
    }

    /** Evaluate a flow and emit alerts if thresholds are crossed. */
    public void evaluate(Flow flow) {
        long pkts  = flow.getPacketCount();
        long bytes = flow.getByteCount();
        int  dstPort = flow.tuple.dstPort;

        // ── Blocked flow alert ─────────────────────────────────
        if (flow.blocked && !flow.alerted) {
            flow.alerted = true;
            emit(new Alert(Severity.WARNING,
                    "Traffic Blocked",
                    flow.blockReason + " → " + (flow.sni.isEmpty() ? flow.tuple.dstIp : flow.sni),
                    flow.tuple.srcIp,
                    flow.appType));
        }

        // ── High packet rate ───────────────────────────────────
        if (!flow.alerted) {
            if (pkts >= criticalPacketRateThreshold) {
                flow.alerted = true;
                emit(new Alert(Severity.CRITICAL,
                        "Extreme Packet Rate",
                        "Flow has " + pkts + " packets — possible DDoS or flood",
                        flow.tuple.srcIp, flow.appType));
            } else if (pkts == highPacketRateThreshold) {
                emit(new Alert(Severity.WARNING,
                        "High Packet Rate",
                        "Flow reached " + pkts + " packets from " + flow.tuple.srcIp,
                        flow.tuple.srcIp, flow.appType));
            }
        }

        // ── High bandwidth ─────────────────────────────────────
        if (bytes >= highByteThreshold && bytes - flow.getByteCount() < 1024) {
            // Only alert once when threshold is crossed
            emit(new Alert(Severity.WARNING,
                    "High Bandwidth Usage",
                    String.format("%.1f MB transferred in flow to %s",
                            bytes / (1024.0 * 1024), flow.tuple.dstIp),
                    flow.tuple.srcIp, flow.appType));
        }

        // ── Suspicious destination port ────────────────────────
        if (SUSPICIOUS_PORTS.contains(dstPort) && pkts == 1) {
            emit(new Alert(Severity.WARNING,
                    "Suspicious Port",
                    "Connection to port " + dstPort + " on " + flow.tuple.dstIp +
                            " (" + portName(dstPort) + ")",
                    flow.tuple.srcIp, flow.appType));
        }

        // ── TikTok / suspicious social apps ───────────────────
        if (flow.appType == AppType.TIKTOK && pkts == 1) {
            emit(new Alert(Severity.INFO,
                    "TikTok Traffic Detected",
                    "Traffic to TikTok from " + flow.tuple.srcIp,
                    flow.tuple.srcIp, AppType.TIKTOK));
        }
    }

    private void emit(Alert alert) {
        alertLog.add(alert);
        listeners.forEach(l -> l.accept(alert));
    }

    public List<Alert> getAlertLog() {
        return Collections.unmodifiableList(alertLog);
    }

    public int getAlertCount() { return alertLog.size(); }

    public long countBySeverity(Severity sev) {
        return alertLog.stream().filter(a -> a.severity == sev).count();
    }

    private static String portName(int port) {
        return switch (port) {
            case 23   -> "Telnet";
            case 445  -> "SMB";
            case 1433 -> "MSSQL";
            case 3389 -> "RDP";
            case 4444 -> "Metasploit";
            case 6667 -> "IRC/Botnet";
            case 8080 -> "Alt-HTTP";
            case 9001 -> "Tor";
            default   -> "Unknown";
        };
    }
}
