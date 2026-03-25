package com.dpianalyzer.core;

import com.dpianalyzer.alerts.AlertEngine;
import com.dpianalyzer.model.AppType;
import com.dpianalyzer.model.FiveTuple;
import com.dpianalyzer.model.PacketInfo;
import com.dpianalyzer.model.Flow;
import com.dpianalyzer.parser.PacketParser;
import com.dpianalyzer.parser.PcapReader;
import com.dpianalyzer.rules.RuleManager;
import com.dpianalyzer.sni.AppClassifier;
import com.dpianalyzer.sni.HTTPHostExtractor;
import com.dpianalyzer.sni.SNIExtractor;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

public class DPIEngine {

    private final int workerThreads;
    private final RuleManager ruleManager;
    private final AlertEngine alertEngine;

    private ExecutorService workers;
    private CountDownLatch workerLatch;

    // Sentinel value — empty array signals end of stream
    private static final byte[] POISON = new byte[0];
    private final BlockingQueue<byte[]> packetQueue = new LinkedBlockingQueue<>(50_000);

    private final ConcurrentHashMap<FiveTuple, Flow> flowTable = new ConcurrentHashMap<>();

    private final AtomicLong totalPackets   = new AtomicLong();
    private final AtomicLong totalBytes     = new AtomicLong();
    private final AtomicLong droppedPackets = new AtomicLong();
    private final AtomicLong tcpPackets     = new AtomicLong();
    private final AtomicLong udpPackets     = new AtomicLong();
    private final ConcurrentHashMap<AppType, AtomicLong> appStats = new ConcurrentHashMap<>();

    private Consumer<PacketInfo> onPacketProcessed;
    private Consumer<Flow>       onFlowUpdated;
    private Runnable             onComplete;

    private volatile boolean running = false;
    private volatile boolean readerDone = false;

    public DPIEngine(int workerThreads, RuleManager ruleManager, AlertEngine alertEngine) {
        this.workerThreads = workerThreads;
        this.ruleManager   = ruleManager;
        this.alertEngine   = alertEngine;
        for (AppType t : AppType.values()) appStats.put(t, new AtomicLong());
    }

    public void setOnPacketProcessed(Consumer<PacketInfo> cb) { this.onPacketProcessed = cb; }
    public void setOnFlowUpdated(Consumer<Flow> cb)           { this.onFlowUpdated = cb; }
    public void setOnComplete(Runnable cb)                    { this.onComplete = cb; }

    public void startAsync(String pcapPath) {
        running    = true;
        readerDone = false;
        workerLatch = new CountDownLatch(workerThreads);
        workers = Executors.newFixedThreadPool(workerThreads);

        // Launch workers first
        for (int i = 0; i < workerThreads; i++) {
            workers.submit(this::workerLoop);
        }

        // Launch reader thread
        Thread reader = new Thread(() -> readerLoop(pcapPath), "pcap-reader");
        reader.setDaemon(true);
        reader.start();

        // Watcher fires onComplete after all workers finish
        Thread watcher = new Thread(() -> {
            try {
                workerLatch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            running = false;
            if (onComplete != null) onComplete.run();
        }, "completion-watcher");
        watcher.setDaemon(true);
        watcher.start();
    }

    public void stop() {
        running = false;
        // Drain the queue and send poison pills
        packetQueue.clear();
        for (int i = 0; i < workerThreads; i++) {
            packetQueue.offer(POISON);
        }
        if (workers != null) workers.shutdown();
    }

    // ── Reader Thread ──────────────────────────────────────────────
    private void readerLoop(String path) {
        int readCount = 0;
        try (PcapReader reader = new PcapReader()) {
            reader.open(path);
            PcapReader.RawPacket raw;
            while ((raw = reader.readNextPacket()) != null) {
                if (!running) break;
                if (raw.data.length > 0) {
                    packetQueue.put(raw.data);
                    readCount++;
                }
            }
            System.out.println("[Reader] Finished reading " + readCount + " packets");
        } catch (IOException e) {
            System.err.println("[Reader] PCAP error: " + e.getMessage());
            e.printStackTrace();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            readerDone = true;
            // Send one poison pill per worker
            for (int i = 0; i < workerThreads; i++) {
                try { packetQueue.put(POISON); }
                catch (InterruptedException ignored) {}
            }
        }
    }

    // ── Worker Thread ──────────────────────────────────────────────
    private void workerLoop() {
        try {
            while (true) {
                // Keep draining until poison pill received
                byte[] raw = packetQueue.poll(500, TimeUnit.MILLISECONDS);
                if (raw == null) {
                    // Timeout — check if reader is done and queue is empty
                    if (readerDone && packetQueue.isEmpty()) break;
                    continue;
                }
                if (raw == POISON || raw.length == 0) break; // Poison pill
                processPacket(raw);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            workerLatch.countDown();
        }
    }

    // ── Core Packet Processing ─────────────────────────────────────
    private void processPacket(byte[] raw) {
        PacketInfo pkt = PacketParser.parse(raw);
        if (pkt == null) return;

        totalPackets.incrementAndGet();
        totalBytes.addAndGet(pkt.totalLength);
        if (pkt.hasTcp) tcpPackets.incrementAndGet();
        if (pkt.hasUdp) udpPackets.incrementAndGet();

        Flow flow = flowTable.computeIfAbsent(pkt.tuple, Flow::new);
        flow.recordPacket(pkt.totalLength);

        // DPI — SNI / HTTP Host extraction
        if (flow.appType == AppType.UNKNOWN || flow.sni.isEmpty()) {
            if (pkt.tuple.dstPort == 443 && pkt.payload.length > 5) {
                SNIExtractor.extract(pkt.payload).ifPresent(sni -> {
                    flow.sni     = sni;
                    flow.appType = AppClassifier.classify(sni);
                });
            } else if (pkt.tuple.dstPort == 80 && pkt.payload.length > 5) {
                HTTPHostExtractor.extract(pkt.payload).ifPresent(host -> {
                    flow.sni     = host;
                    flow.appType = AppClassifier.classify(host);
                });
            }
            if (flow.appType == AppType.UNKNOWN) {
                flow.appType = AppClassifier.classifyByPort(pkt.tuple.dstPort);
            }
        }

        appStats.get(flow.appType).incrementAndGet();

        if (!flow.blocked) {
            String reason = ruleManager.checkBlocked(
                pkt.tuple.srcIp, flow.appType, flow.sni);
            if (reason != null) {
                flow.blocked     = true;
                flow.blockReason = reason;
                droppedPackets.incrementAndGet();
            }
        } else {
            droppedPackets.incrementAndGet();
        }

        alertEngine.evaluate(flow);
        if (onPacketProcessed != null) onPacketProcessed.accept(pkt);
        if (onFlowUpdated != null)     onFlowUpdated.accept(flow);
    }

    // ── Accessors ──────────────────────────────────────────────────
    public long getTotalPackets()   { return totalPackets.get(); }
    public long getTotalBytes()     { return totalBytes.get(); }
    public long getDroppedPackets() { return droppedPackets.get(); }
    public long getForwarded()      { return totalPackets.get() - droppedPackets.get(); }
    public long getTcpPackets()     { return tcpPackets.get(); }
    public long getUdpPackets()     { return udpPackets.get(); }

    public Map<AppType, Long> getAppStats() {
        Map<AppType, Long> result = new LinkedHashMap<>();
        appStats.forEach((k, v) -> { if (v.get() > 0) result.put(k, v.get()); });
        return result;
    }

    public Collection<Flow> getFlows() {
        return Collections.unmodifiableCollection(flowTable.values());
    }

    public int     getFlowCount() { return flowTable.size(); }
    public boolean isRunning()    { return running; }
}
