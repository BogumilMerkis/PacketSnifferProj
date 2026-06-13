<div align="center">

# 🛰️ PacketSniffer

### A real-time packet & connection analyzer with an IDS-style detection engine

A web-based network analyzer in the spirit of Wireshark - but built around a **decoupled, high-throughput capture pipeline** and a **two-layer intrusion-detection engine** that flags scans, floods, spoofing, tunnelling and exploit traffic in real time, maps them to **MITRE ATT&CK**, and ships them to your SIEM and chat-ops.

![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet&logoColor=white)
![C#](https://img.shields.io/badge/C%23-12-239120?logo=csharp&logoColor=white)
![Tests](https://img.shields.io/badge/tests-51%20passing-success)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)
![Detection](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)

<img width="1914" height="946" alt="PacketSniffer dashboard" src="https://github.com/user-attachments/assets/ebd7d9ae-abe6-4e1f-84bd-269aab7cb4fe" />

</div>

---

## ✨ Highlights

- **Real-time capture that doesn't choke under load.** The capture thread does nothing but persist raw frames and hand bytes to a bounded channel; a background worker decodes once, detects, and the UI is fed coalesced batches over a WebSocket. Full per-packet decode + hex is fetched *on demand* - so a packet flood never hangs the browser.
- **Two-layer detection engine** - stateless Suricata-style signatures **and** stateful 5-tuple flow analysis, every hit tagged with a stable SID, severity, category and **MITRE ATT&CK** technique.
- **Standards-aligned security logging** - every alert is written as structured **ECS** (Elastic Common Schema) or **CEF** (ArcSight) to a rolling audit log, ready for Elastic/Kibana or any SIEM.
- **Pluggable alert notifications** - fan alerts out to **Slack/Discord/webhooks** (HMAC-signed), **syslog/SIEM** (RFC 5424), and **email** - plus in-browser toasts, sound, and desktop notifications.
- **Offline analysis** - upload a `.pcap`/`.pcapng` and replay it through the exact same detection pipeline; download the live capture as pcap.
- **Built for remote use** - listens on `0.0.0.0:5000`, HTTP Basic auth on every endpoint, designed for headless/SSH deployment.

---

## 🏗️ Architecture

The backend is an IDS-style **decoupled producer/consumer pipeline**. The key to its performance: the capture callback never decodes or serializes anything.

```
 [NIC]
   │  OnPacketArrival  (capture thread: write pcap + enqueue RAW bytes - nothing else)
   ▼
 bounded Channel<RawFrame>            ← drop-oldest back-pressure; the NIC reader never blocks
   │
   ▼
 analysis worker                      ← decode ONCE → SignatureEngine + FlowTracker → ring buffer
   │
   ├──► BroadcastHub      (coalesce + serialize once per ~250 ms tick → fan out to all WS clients)
   ├──► SecurityEventLog  (one ECS/CEF line per alert → rolling Logs/ file)
   └──► NotificationQueue (non-blocking enqueue → background dispatcher → webhook / syslog / email)
```

| Component | Responsibility |
|-----------|----------------|
| `CaptureSession` | Orchestrator - owns the device, channel, analysis worker and janitor; shared by live capture and pcap replay. |
| `SignatureEngine` | Stateless, per-packet rules (Suricata-style SIDs). |
| `FlowTracker` | Stateful 5-tuple analysis - scans, floods, long-lived connections, flow entropy. |
| `BroadcastHub` | WebSocket registry + fixed-interval flush; serializes one batch and reuses the buffer across clients. |
| `PacketRingBuffer` | Bounded recent-packet store for on-demand full decode + hex. |
| `AlertStore` | Bounded alert log with `(sid, src, dst)` time-based suppression - a scan yields *one* alert, not thousands. |
| `SecurityEventLog` | Bespoke structured audit log (ECS / CEF) via Serilog rolling files. |
| `NotificationDispatcher` | Background service fanning alerts to pluggable channels by severity threshold. |

---

## 🔍 Detection coverage

Every rule carries a stable **SID**, **severity**, **category** and (where applicable) a **MITRE ATT&CK** technique. Verdict (Benign / Suspicious / Malicious) is derived from the max severity of matched rules.

### Stateless signatures (`SignatureEngine`)

| SID | Detection | Severity | MITRE |
|-----|-----------|----------|-------|
| PS-1001 | Broadcast source MAC | High | T1557 |
| PS-1002 | Gratuitous ARP | Medium | T1557.002 |
| PS-1003 | ARP MAC mismatch (poisoning) | High | T1557.002 |
| PS-2003 | LAND attack | High | T1499 |
| PS-2004 | IP fragmentation evasion | Low | T1599 |
| PS-3001 | ICMP tunnel / oversized payload | Medium | T1048.003 |
| PS-3002 | TCP NULL scan | Medium | T1046 |
| PS-3003 | TCP SYN+FIN (invalid combo) | Medium | T1046 |
| PS-3004 | TCP Xmas scan (FIN+PSH+URG) | Medium | T1046 |
| PS-3006/7 | Reflection port loop (TCP/UDP) | Medium | T1499 |
| PS-4001 | Exploit signature in payload | High | T1190 |
| PS-4002 | High-entropy payload on cleartext port | Medium | T1048 |
| PS-4003 | Possible DNS tunnelling | Medium | T1048.003 |

*(plus malformed-header and anomalous-addressing checks: PS-2001/2002/2005, PS-3005)*

### Stateful flow analysis (`FlowTracker`)

| SID | Detection | Severity | MITRE |
|-----|-----------|----------|-------|
| PS-5001 | SYN flood / half-open scan | High | T1499.001 |
| PS-5002 | Sustained high packet rate | Medium | T1499 |
| PS-5003 | Long-lived unclosed connection | Low | T1071 |
| PS-5004 | High-entropy flow on cleartext port | Medium | T1048 |
| PS-5005 | Vertical port scan | High | T1046 |
| PS-5006 | Horizontal host sweep | High | T1046 |

---

## 📑 Alerting, logging & notifications

Each un-suppressed alert is fanned out three ways - all **off the capture hot-path**:

**1. Live UI** - the WebSocket Alerts view, plus optional **in-browser notifications**. Click **Enable Alerts** for a toast, a sound, and (when the tab is hidden) an OS desktop notification on High/Critical alerts. Throttled per-rule to avoid alert fatigue.

**2. Bespoke security audit log** (`Logs/`, daily-rolling) - one structured line per alert in a format chosen via config:

<table>
<tr><th>ECS (default)</th><th>CEF</th></tr>
<tr><td>

```json
{
  "@timestamp": "2026-06-13T14:22:31.001Z",
  "event": { "kind": "alert",
    "category": ["intrusion_detection","network"] },
  "source": { "ip": "192.0.2.55", "port": 49321 },
  "destination": { "ip": "10.0.0.10", "port": 445 },
  "threat": { "technique": { "id": ["T1046"] },
    "tactic": { "id": ["TA0007"] } },
  "rule": { "id": "PS-5005", "name": "Vertical Port Scan" },
  "observer": { "type": "ids" }
}
```

</td><td>

```
CEF:0|PacketSniffer|FYP-IDS|1.0|PS-5005|
Vertical Port Scan|7|src=192.0.2.55
dst=10.0.0.10 spt=49321 dpt=445 proto=TCP
act=detected cs1Label=MitreTechnique
cs1=T1046 cs2Label=Category cs2=Reconnaissance
```

</td></tr>
</table>

Application logs use **Serilog** (console + rolling `Logs/app-*.log`).

**3. Notification channels** - a non-blocking dispatcher delivers alerts above a per-channel severity threshold:

| Channel | Format | Notes |
|---------|--------|-------|
| **Webhook** | Slack / Discord / generic JSON | optional HMAC-SHA256 body signature (`X-Signature`), retries w/ backoff |
| **Syslog** | RFC 5424 over UDP/TCP | for SIEM / collector forwarding |
| **Email** | SMTP via MailKit | digest-style for High/Critical |

All channels are **disabled by default**.

---

## 🚀 Getting started

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download)
- **Npcap** (Windows) or **libpcap** (Linux) for live capture - usually with elevated privileges
- *(offline pcap replay works without elevation)*

### Run

```bash
dotnet run                       # serves http://0.0.0.0:5000
```

Open the dashboard, pick an interface, optionally set a BPF filter (e.g. `tcp port 80`), and hit **Start**. Or **Upload** a `.pcap` to analyse it offline.

### Authentication

Every endpoint except `/health` requires HTTP Basic auth. Credentials resolve from `MASTER_USER` / `MASTER_PASS_HASH` env vars, then `Auth:User` / `Auth:PassHash` config.

```bash
# generate a PBKDF2 salt:hash pair with Auth.HashPassword("your-password")
export MASTER_USER=admin
export MASTER_PASS_HASH="<base64Salt>:<base64Hash>"
```

For local development, copy `appsettings.Secrets.json.example` → `appsettings.Secrets.json` (gitignored).

---

## ⚙️ Configuration

All tunables bind from `appsettings.json` (secrets in the gitignored `appsettings.Secrets.json`).

| Section | Purpose |
|---------|---------|
| `Sniffer` | Pipeline sizing, detection thresholds, broadcast interval, alert suppression window |
| `SecurityLog` | Audit-log format (`Ecs`/`Cef`), directory, retention, size cap |
| `Notifications` | Per-channel enable flags, severity thresholds, endpoints |

Example - enable a Slack webhook and syslog forwarding (in `appsettings.Secrets.json`):

```json
{
  "Notifications": {
    "Webhook": { "Enabled": true, "MinSeverity": "High", "Flavor": "Slack",
                 "Url": "https://hooks.slack.com/services/T000/B000/XXXX" },
    "Syslog":  { "Enabled": true, "MinSeverity": "Medium",
                 "Host": "siem.example.local", "Port": 514, "Protocol": "Udp" }
  }
}
```

---

## 🌐 API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness probe *(no auth)* |
| `GET` | `/devices` | List capture interfaces |
| `POST` | `/start?devIndex=&filter=` | Begin capture (optional BPF filter) |
| `POST` | `/stop` | Stop capture |
| `GET` | `/status` | Live counters (captured / analyzed / dropped / flows / clients) |
| `GET` | `/alerts` | Recent alerts |
| `GET` | `/packet/{id}` | Full decode + hex dump for one packet (on demand) |
| `GET` | `/download` | Download the session pcap |
| `POST` | `/upload` | Replay an uploaded pcap through the pipeline |
| `WS` | `/ws` | Batched live feed (`?auth=base64(user:pass)`) |

**Wire protocol:** camelCase JSON throughout. The WS message is
`{ type:"batch", packets:[…], flows:[…], alerts:[…], stats:{…} }`.

---

## 🧪 Testing

```bash
dotnet test PacketSniffer.Tests
```

**51 xUnit tests** cover the detection engine, alert suppression, the ring buffer, packet decoding, the ECS/CEF/RFC-5424 formatters (incl. escaping & severity mapping), webhook payloads, HMAC signing, severity-threshold routing, the audit log writing to disk, and the notification dispatcher end-to-end.

---

## 🛠️ Tech stack

**Backend:** ASP.NET Core (.NET 8) minimal API · [SharpPcap](https://github.com/dotpcap/sharppcap) + [PacketDotNet](https://github.com/dotpcap/packetnet) · [Serilog](https://serilog.net/) · [MailKit](https://github.com/jstedfast/MailKit)
**Frontend:** AngularJS 1.x · [Grid.js](https://gridjs.io/) · Bootstrap 5
**Standards:** MITRE ATT&CK · Elastic Common Schema · ArcSight CEF · RFC 5424 (syslog)

---

## 📂 Project layout

```
PacketSniffer/
├── Program.cs                 # host, DI, auth middleware, endpoints, Serilog setup
├── Auth.cs                    # PBKDF2 HTTP Basic auth
├── Core/
│   ├── CaptureSession.cs      # capture orchestrator + analysis loop
│   ├── SignatureEngine.cs     # stateless per-packet rules
│   ├── FlowTracker.cs         # stateful 5-tuple flow analysis
│   ├── BroadcastHub.cs        # WebSocket batching/fan-out
│   ├── AlertStore.cs          # bounded, suppressed alert log
│   ├── MitreAttack.cs         # technique → tactic enrichment
│   ├── Logging/               # ECS + CEF formatters, SecurityEventLog
│   └── Notifications/         # queue, dispatcher, webhook/syslog/email channels
├── wwwroot/                   # AngularJS + Grid.js single-page UI
└── PacketSniffer.Tests/       # xUnit suite
```

---

<div align="center">

*Final-year university project - a hands-on exploration of high-throughput packet capture, network intrusion detection, and security-event standardisation.*

</div>
