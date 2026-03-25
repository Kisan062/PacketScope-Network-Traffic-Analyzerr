# 🔍 DPI Packet Analyzer - Java 

> A Deep Packet Inspection engine rebuilt in Java with a **Live GUI Dashboard**, **Real-time Alerts**, and a **multi-threaded processing pipeline** — inspired by the C++ original but with powerful Java-native enhancements.

---

## ✨ What Makes This Unique 

| Feature | C++ Original | Java  |
|---|---|---|
| Language | C++ (manual memory) | Java 17+ (managed, safe) |
| GUI | ❌ None (CLI only) | ✅ Live Swing Dashboard |
| Alerts | ❌ None | ✅ Real-time alert feed (threshold, suspicious ports, blocked flows) |
| Charts | ❌ None | ✅ Live Pie + Bar charts (JFreeChart) |
| Thread model | Raw pthreads | `ExecutorService` thread pool |
| Flow table | `std::unordered_map` | `ConcurrentHashMap` (lock-free) |
| PCAP generation | Python script | ✅ Pure Java `PcapGenerator` |
| Rule management | CLI flags only | ✅ GUI Rules Dialog (runtime editable) |
| App detection | 10 apps | ✅ 20 apps (Discord, Zoom, Telegram, etc.) |
| HTTP host extraction | Basic | ✅ Full HTTP/1.x Host header parsing |

---

## 🏗️ Project Structure

```
dpi-packet-analyzer/
├── pom.xml                                     ← Maven build file
└── src/main/java/com/dpianalyzer/
    ├── Main.java                               ← Entry point (launches GUI)
    │
    ├── model/
    │   ├── FiveTuple.java                      ← Connection identifier (5 fields)
    │   ├── AppType.java                        ← Enum: YouTube, Netflix, TikTok...
    │   ├── Flow.java                           ← Tracked connection state
    │   ├── PacketInfo.java                     ← Parsed packet data
    │   └── Alert.java                          ← Security/policy alert
    │
    ├── parser/
    │   ├── PcapReader.java                     ← Reads .pcap binary files
    │   └── PacketParser.java                   ← Parses Ethernet/IP/TCP/UDP headers
    │
    ├── sni/
    │   ├── SNIExtractor.java                   ← Extracts domain from TLS Client Hello
    │   ├── HTTPHostExtractor.java              ← Extracts Host from HTTP requests
    │   └── AppClassifier.java                  ← Maps domain → AppType (20 apps)
    │
    ├── rules/
    │   └── RuleManager.java                    ← Thread-safe: block IPs / apps / domains
    │
    ├── alerts/
    │   └── AlertEngine.java                    ← Real-time alert generation + listener callbacks
    │
    ├── core/
    │   └── DPIEngine.java                      ← Multi-threaded orchestrator
    │
    ├── gui/
    │   ├── DashboardGUI.java                   ← Live Swing dashboard (charts + flow table)
    │   └── RulesDialog.java                    ← Runtime rule management dialog
    │
    └── util/
        └── PcapGenerator.java                  ← Generates synthetic .pcap test files (pure Java)
```

---

## 🚀 How to Build & Run

### Prerequisites
- Java 17 or higher
- Maven 3.6+

### Build
```bash
cd dpi-packet-analyzer
mvn clean package -q
```
This produces `target/dpi-analyzer-full.jar` (fat JAR with all dependencies).

### Run (GUI Mode)
```bash
java -jar target/dpi-analyzer-full.jar
```

### Quick Start in the GUI
1. Click **⚡ Generate Test PCAP** — creates 500 synthetic packets instantly (no Wireshark needed)
2. Click **▶ Start** — engine starts processing
3. Watch the **Live Pie Chart** and **Bar Chart** update in real time
4. Check the **🚨 Live Alerts** panel on the right for security events
5. Click **🛡 Rules** to block apps, IPs, or domains mid-analysis

---

## 🖥️ Dashboard Layout

```
┌──────────────────────────────────────────────────────────────────────┐
│  HEADER: Title | File path | Generate | Open | ▶ Start | ⏹ Stop | Rules │
├───────────────────┬──────────────────────┬───────────────────────────┤
│   STAT CARDS      │   PIE CHART          │   🚨 LIVE ALERT FEED      │
│  • Total Packets  │   App Breakdown      │   Real-time color-coded   │
│  • Forwarded      │   (auto-updating)    │   alert entries           │
│  • Dropped        │                      │                           │
│  • Active Flows   │                      │                           │
│  • Alerts         │                      │                           │
│  • Throughput B/s │                      │                           │
├───────────────────┴──────────────────────┴───────────────────────────┤
│  BAR CHART (Top 10 apps by packet count)  │  FLOW TABLE (scrollable) │
│                                           │  100 active flows shown   │
│                                           │  Blocked rows highlighted │
└───────────────────────────────────────────┴───────────────────────────┘
```

---

## 🏛️ Architecture Deep Dive

### Multi-threaded Pipeline

```
PCAP File
    │
    ▼
┌─────────────┐   byte[]    ┌──────────────────────┐
│ Reader      │ ──────────► │ BlockingQueue<byte[]> │ (capacity: 10,000)
│ Thread      │             └──────────┬───────────┘
└─────────────┘                        │
                                       ▼  (4 worker threads)
                            ┌─────────────────────────┐
                            │ Worker Thread Pool       │
                            │  1. Parse Ethernet/IP/TCP│
                            │  2. Extract SNI / Host   │
                            │  3. Classify App         │
                            │  4. Check Blocking Rules │
                            │  5. Fire Alert checks    │
                            │  6. Notify GUI callbacks │
                            └──────────┬──────────────┘
                                       │
                          ┌────────────┴──────────────┐
                          ▼                            ▼
                   ConcurrentHashMap            AtomicLong counters
                   (FiveTuple → Flow)           (lock-free stats)
                          │
                          ▼
                   GUI callbacks (Consumer<T>)
                   → Swing EDT via invokeLater
```

### Key Java Design Patterns Used

| Pattern | Where | Why |
|---|---|---|
| **Producer-Consumer** | Reader → BlockingQueue → Workers | Decouples I/O from processing |
| **Observer** | AlertEngine listeners | GUI subscribes to alerts |
| **Strategy** | AppClassifier rules map | Easy to extend with new apps |
| **Template Method** | PacketParser | Fixed parsing order, extensible |
| **ConcurrentHashMap** | Flow table | Lock-free per-key operations |
| **AtomicLong** | Stats counters | Zero contention counting |

---

## 🔒 How SNI Extraction Works

Even HTTPS is encrypted — but the **TLS Client Hello** is sent before encryption starts, and it contains the domain name in **plaintext**:

```
TLS Record (Handshake):
  Content-Type: 0x16
  Handshake-Type: 0x01 (Client Hello)
  ...
  Extensions:
    Type: 0x0000 (SNI)
    Value: "www.youtube.com"  ← We read THIS
```

After extraction: `"www.youtube.com"` → classified as `AppType.YOUTUBE`.

---

## 🚨 Alert Types

| Alert | Severity | Trigger |
|---|---|---|
| Traffic Blocked | ⚠️ WARNING | Flow matched a blocking rule |
| High Packet Rate | ⚠️ WARNING | Flow exceeds 500 packets |
| Extreme Packet Rate | 🚨 CRITICAL | Flow exceeds 2000 packets (possible DDoS) |
| High Bandwidth | ⚠️ WARNING | Flow transfers > 10 MB |
| Suspicious Port | ⚠️ WARNING | Destination port: Telnet/SMB/RDP/Metasploit/Tor/IRC |
| TikTok Detected | ℹ️ INFO | First packet to TikTok detected |

---

## 🛡️ Blocking Rules

Three rule types, all editable at runtime via the GUI:

```
Block by IP:     192.168.1.50   → drops ALL traffic from this source
Block by App:    YouTube        → drops all flows classified as YouTube
Block by Domain: tiktok         → drops any SNI containing "tiktok" (substring)
```

Rules are stored in `CopyOnWriteArraySet` — safe to modify while workers run.

---

## 📦 Dependencies

| Library | Purpose |
|---|---|
| `org.jfree:jfreechart:1.5.4` | Live pie + bar charts in the dashboard |
| `org.apache.commons:commons-csv:1.10.0` | CSV export (extendable) |
| `org.slf4j:slf4j-simple:2.0.9` | Logging |

No native libraries. No `libpcap`. Runs on any OS with Java 17+.

---

## 🔧 Extending the Project

### Add a new app (e.g., Spotify)
In `AppType.java`:
```java
SPOTIFY("Spotify", "🎵"),
```
In `AppClassifier.java`:
```java
RULES.put("spotify", AppType.SPOTIFY);
RULES.put("scdn.co", AppType.SPOTIFY); // Spotify CDN
```

### Add a new alert type
In `AlertEngine.java`:
```java
if (flow.appType == AppType.SPOTIFY && pkts == 1) {
    emit(new Alert(Severity.INFO, "Spotify Detected", ..., AppType.SPOTIFY));
}
```

### Increase worker threads
In `DashboardGUI.java`, change:
```java
engine = new DPIEngine(8, ruleManager, alertEngine); // 8 workers
```


