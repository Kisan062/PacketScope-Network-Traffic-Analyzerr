<div align="center">

# 🔍 DPI Packet Analyzer

### Deep Packet Inspection Engine — Java Edition

[![Java](https://img.shields.io/badge/Java-23-orange?style=for-the-badge&logo=openjdk)](https://openjdk.org/)
[![Maven](https://img.shields.io/badge/Maven-3.9-red?style=for-the-badge&logo=apachemaven)](https://maven.apache.org/)
[![JFreeChart](https://img.shields.io/badge/JFreeChart-1.5.4-blue?style=for-the-badge)](https://www.jfree.org/jfreechart/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> A production-grade **Deep Packet Inspection** system built in Java — featuring a **live GUI dashboard**, **real-time security alerts**, **multi-threaded packet processing**, and **TLS SNI extraction** — capable of classifying network traffic across 20+ applications without any native libraries.

[Features](#-features) • [Architecture](#-architecture) • [Getting Started](#-getting-started) • [How It Works](#-how-it-works) • [Screenshots](#-dashboard-preview)

---

</div>

## 🎯 What Is This?

When you visit `https://www.youtube.com`, your browser sends a **TLS Client Hello** — and buried inside that handshake, in **plain text**, is the domain name. This project captures that moment.

The **DPI Packet Analyzer** reads raw network captures (`.pcap` files), tears apart every Ethernet frame byte-by-byte, extracts hidden domain names from encrypted HTTPS traffic, classifies connections by application, enforces blocking rules, and renders everything in a live dashboard — all in real time.

This is the kind of technology used by ISPs, enterprise firewalls, and parental control systems — rebuilt from scratch in pure Java.

---

## ✨ Features

### 🖥️ Live GUI Dashboard
- Real-time stat cards updating every **500ms** — total packets, forwarded, dropped, active flows, alerts, throughput
- **Live Pie Chart** — traffic breakdown by application (YouTube, Netflix, TikTok, etc.)
- **Live Bar Chart** — top 10 applications by packet volume
- **Flow Table** — scrollable list of 100 active connections with blocked flows highlighted in red
- **Alert Feed** — color-coded real-time security event stream

### 🚨 Real-Time Alert Engine
| Alert Type | Severity | Trigger |
|---|---|---|
| Traffic Blocked | ⚠️ WARNING | Flow matched a blocking rule |
| High Packet Rate | ⚠️ WARNING | Flow exceeds 500 packets |
| Possible DDoS/Flood | 🚨 CRITICAL | Flow exceeds 2,000 packets |
| High Bandwidth | ⚠️ WARNING | Flow transfers > 10 MB |
| Suspicious Port | ⚠️ WARNING | RDP / SMB / Metasploit / Telnet / Tor / IRC |
| App Detected | ℹ️ INFO | First packet to flagged application |

### 🛡️ Runtime Blocking Rules
- **Block by IP** — drop all traffic from a specific source
- **Block by App** — block entire applications (YouTube, TikTok, Discord, etc.)
- **Block by Domain** — substring keyword match on SNI (`tiktok`, `netflix`, etc.)
- All rules are **editable while the engine runs** — no restart needed

### ⚡ Multi-Threaded Processing Pipeline
- 4 parallel worker threads drain a `BlockingQueue<byte[]>`
- `ConcurrentHashMap` for lock-free flow state management
- `AtomicLong` counters — zero contention statistics
- `CountDownLatch` for precise completion signalling
- GUI callbacks via `Consumer<T>` → `SwingUtilities.invokeLater`

### 🔬 Deep Packet Inspection
- Parses raw **Ethernet → IPv4 → TCP/UDP** frames from binary `.pcap` files
- Extracts **SNI** (Server Name Indication) from **TLS Client Hello** — works on encrypted HTTPS
- Extracts **Host header** from plain HTTP requests
- Classifies traffic across **20 applications**: YouTube, Netflix, TikTok, Instagram, Facebook, Twitter, Discord, Zoom, WhatsApp, Telegram, GitHub, Amazon, Microsoft, Apple, Cloudflare, and more

---

## 🏗️ Architecture

```
                    ┌─────────────────────────┐
                    │     PcapReader           │
                    │  (binary file parser)    │
                    └────────────┬────────────┘
                                 │  byte[]
                                 ▼
                    ┌─────────────────────────┐
                    │   BlockingQueue<byte[]>  │  capacity: 50,000
                    │   (backpressure buffer)  │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       ┌────────────┐    ┌────────────┐    ┌────────────┐
       │  Worker 1  │    │  Worker 2  │    │  Worker N  │
       │            │    │            │    │            │
       │ 1. Parse   │    │ 1. Parse   │    │ 1. Parse   │
       │ 2. SNI/DPI │    │ 2. SNI/DPI │    │ 2. SNI/DPI │
       │ 3. Classify│    │ 3. Classify│    │ 3. Classify│
       │ 4. Rules   │    │ 4. Rules   │    │ 4. Rules   │
       │ 5. Alerts  │    │ 5. Alerts  │    │ 5. Alerts  │
       └─────┬──────┘    └─────┬──────┘    └─────┬──────┘
             └────────────────┬────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
              ▼                               ▼
   ConcurrentHashMap                   AtomicLong counters
   FiveTuple → Flow                    (lock-free stats)
              │
              ▼
   Consumer<T> callbacks
   → SwingUtilities.invokeLater()
   → Live Dashboard updates
```

### Key Design Decisions

| Decision | What | Why |
|---|---|---|
| `BlockingQueue` | Producer-consumer buffer | Decouples I/O from CPU — reader never blocks workers |
| `ConcurrentHashMap` | Flow state table | Per-key locking — no global mutex bottleneck |
| `AtomicLong` | Stats counters | Compare-and-swap — faster than `synchronized` |
| `CountDownLatch` | Completion tracking | Workers signal done without polling |
| `Consumer<T>` callbacks | GUI hooks | Clean separation — engine knows nothing about Swing |
| `SwingUtilities.invokeLater` | UI updates | Thread-safe — all Swing calls on EDT |
| Explicit imports | No `model.*` wildcard | Avoids `java.util.concurrent.Flow` clash |

---

## 📦 Project Structure

```
dpi-packet-analyzer/
├── pom.xml
└── src/main/java/com/dpianalyzer/
    │
    ├── Main.java                        ← Entry point (GUI + --debug mode)
    │
    ├── model/
    │   ├── FiveTuple.java               ← Connection key: srcIP:port → dstIP:port + proto
    │   ├── AppType.java                 ← Enum: 20 classified applications
    │   ├── Flow.java                    ← Stateful connection tracker
    │   ├── PacketInfo.java              ← Parsed packet snapshot
    │   └── Alert.java                   ← Security event with severity + timestamp
    │
    ├── parser/
    │   ├── PcapReader.java              ← Binary .pcap reader (auto byte-order detection)
    │   └── PacketParser.java            ← Ethernet/IPv4/TCP/UDP header parser
    │
    ├── sni/
    │   ├── SNIExtractor.java            ← TLS Client Hello → domain name
    │   ├── HTTPHostExtractor.java       ← HTTP Host header extractor
    │   └── AppClassifier.java           ← Domain → AppType (ordered rules map)
    │
    ├── rules/
    │   └── RuleManager.java             ← Thread-safe: CopyOnWriteArraySet rules
    │
    ├── alerts/
    │   └── AlertEngine.java             ← Threshold + port + block alerts + listeners
    │
    ├── core/
    │   └── DPIEngine.java               ← Orchestrator: threads, queues, callbacks
    │
    ├── gui/
    │   ├── DashboardGUI.java            ← Live Swing dashboard
    │   └── RulesDialog.java             ← Runtime rule management dialog
    │
    └── util/
        ├── PcapGenerator.java           ← Synthetic .pcap generator (pure Java)
        └── DebugTest.java               ← Pipeline validation tool
```

---

## 🚀 Getting Started

### Prerequisites
```
Java 17+    →  java -version
Maven 3.6+  →  mvn -version
```

### Build
```bash
git clone https://github.com/yourusername/dpi-packet-analyzer
cd dpi-packet-analyzer/dpi-analyzer
mvn clean package
```

### Run
```bash
# Launch GUI
java -jar target/dpi-analyzer-full.jar

# Run pipeline debug test
java -jar target/dpi-analyzer-full.jar --debug
```

### Quick Start
```
1. Click  "Generate Test PCAP"   →  500 synthetic packets, no Wireshark needed
2. Click  "Start"                →  engine begins multi-threaded processing
3. Watch  live charts update     →  pie chart, bar chart, flow table, alerts
4. Click  "Rules"                →  block YouTube / TikTok / any IP at runtime
5. Click  "Open PCAP"            →  load a real Wireshark capture
```

---

## 🔬 How It Works

### TLS SNI Extraction

Even though HTTPS is encrypted, the **TLS Client Hello** is sent before encryption begins — and it contains the destination domain in **plain text**:

```
TLS Record Header:
  [0x16]          Content-Type: Handshake
  [0x03 0x01]     TLS Version
  [length]        Record length

Handshake Header:
  [0x01]          Type: Client Hello
  [length]        Body length

Client Hello Body:
  [version]       TLS 1.2 / 1.3
  [32 bytes]      Random
  [session ID]    Variable
  [cipher suites] List
  [compression]   Methods
  [extensions]
    Extension Type:   0x0000  ← SNI
    Extension Length: N
      SNI List Length: M
      SNI Type:    0x00       ← hostname
      SNI Length:  L
      SNI Value:   "www.youtube.com"  ← EXTRACTED ✅
```

### Five-Tuple Flow Tracking

Every connection is uniquely identified by:
```
{ srcIP, dstIP, srcPort, dstPort, protocol }
   ↓
  hash → ConcurrentHashMap key → Flow object
```

All packets with the same five-tuple share one `Flow`. Once a flow is blocked, **every subsequent packet** in that connection is dropped — not just the first one.

### Packet Parsing Pipeline

```
Raw bytes (Ethernet frame)
  │
  ├─ [0–13]   Ethernet Header  → EtherType check (0x0800 = IPv4 only)
  ├─ [14–33]  IPv4 Header      → src/dst IP, protocol (6=TCP, 17=UDP), IHL
  ├─ [34–53]  TCP Header       → src/dst port, data offset, SYN/FIN/RST flags
  │   OR
  ├─ [34–41]  UDP Header       → src/dst port, length
  │
  └─ [payload start → end]     → SNIExtractor / HTTPHostExtractor
```

---

## 🆚 Java vs C++ 

| Aspect | C++  | Java |
|---|---|---|
| **GUI** | None — CLI only | ✅ Full live Swing dashboard |
| **Alerts** | None | ✅ Real-time alert engine with 6 alert types |
| **Charts** | None | ✅ Live pie + bar charts (JFreeChart) |
| **Threading** | Raw `pthreads` | `ExecutorService` + `CountDownLatch` |
| **Flow table** | `std::unordered_map` + mutex | `ConcurrentHashMap` (lock-free) |
| **Counters** | Atomic intrinsics | `AtomicLong` (JVM-managed) |
| **Rule updates** | Restart required | ✅ Live updates via `CopyOnWriteArraySet` |
| **PCAP generation** | Python script | ✅ Pure Java `PcapGenerator` |
| **App coverage** | 10 apps | ✅ 20 apps |
| **Debug tooling** | None | ✅ `--debug` pipeline validation mode |
| **Memory safety** | Manual (`new`/`delete`) | JVM garbage collected |

---

## 🧠 Concepts Demonstrated

- **Network Protocol Parsing** — Ethernet, IPv4, TCP, UDP from raw bytes
- **Deep Packet Inspection** — TLS Client Hello SNI extraction
- **Concurrent Programming** — Producer-consumer, lock-free data structures
- **Design Patterns** — Observer, Strategy, Producer-Consumer, Template Method
- **Swing GUI** — EDT-safe updates, custom cell renderers, JFreeChart integration
- **Java I/O** — Binary file parsing with correct endianness handling
- **Systems Thinking** — Backpressure, poison pills, graceful shutdown

---

## 📚 Dependencies

| Library | Version | Purpose |
|---|---|---|
| `org.jfree:jfreechart` | 1.5.4 | Live pie and bar charts |
| `org.apache.commons:commons-csv` | 1.10.0 | CSV export capability |
| `org.slf4j:slf4j-simple` | 2.0.9 | Logging facade |

**No native libraries. No libpcap. No JNI. Runs on any OS with Java 17+.**

<div align="center">

**Built with Java 23 · Maven · JFreeChart · Pure curiosity about what's inside every packet**

</div>
