# 🛡️ DPI Home

**Real-time MikroTik traffic analyzer**

A Windows 10 application that connects to **MikroTik Packet Sniffer** and analyzes traffic in real time, detecting potentially dangerous connections and anomalies.

## 🚀 Features

- **Traffic capture** — direct connection to MikroTik Packet Sniffer (UDP TZSP stream)
- **Deep packet inspection (DPI)** — Ethernet/IP/TCP/UDP header parsing
- **Signature analysis** — known threat detection (EternalBlue, SMBv1, stealth scans, etc.)
- **Behavioral analysis** — port scan, brute-force, RDP brute-force, DNS/ICMP tunneling, SYN flood detection
- **Auto-block** — automatically adds malicious IPs to MikroTik address-list via REST API
- **HTTPS tracking** — real-time inbound HTTPS connection monitoring
- **Modern GUI** — dark Material Design theme, real-time statistics
- **Threat levels** — Info / Low / Medium / High / Critical

## 🔧 Technologies

| Component | Technology |
|-----------|------------|
| Language | C# 12 (.NET 8) |
| GUI | WPF + MaterialDesignInXaml |
| MVVM | CommunityToolkit.Mvvm |
| Parsing | Native (no third-party libraries) |
| Performance | ConcurrentDictionary, lock-free counters, throttled UI updates |

## 📋 Threat signatures

| Threat | Level | Description |
|--------|-------|-------------|
| NULL Scan | 🔴 High | TCP with zero flags |
| XMAS Scan | 🔴 High | FIN+PSH+URG flags |
| FIN Scan | ⚡ Medium | FIN flag only |
| EternalBlue | 💀 Critical | SMBv1 exploit (MS17-010) |
| SMBv1 Exposure | 🔴 High | Legacy SMBv1 traffic on port 445 |
| DNS Tunneling | 🔴 High | UDP DNS payload > 512 bytes |
| ICMP Tunneling | 🔴 High | ICMP payload > 1000 bytes |
| Port Scan | 🔴 High | Behavioral: 20+ unique ports in 10s |
| Brute Force | 💀 Critical | Behavioral: 10+ SYN on SSH/RDP/FTP/SQL ports |
| RDP Brute Force | 💀 Critical | Behavioral: N new RDP connections in M minutes (configurable) |
| SYN Flood | 💀 Critical | Behavioral: 100+ SYN/s with spoofing detection |

## 🖥️ System requirements

- Windows 10 / 11
- MikroTik RouterOS 7+ with Packet Sniffer enabled

## 🔌 MikroTik setup

```bash
# Enable Packet Sniffer streaming to your PC
/tool sniffer set streaming-enabled=yes streaming-server=192.168.x.x:37008 filter-direction=rx filter-interface=WAN
/tool sniffer start
```

For auto-block and WAN-IP auto-detection, enable REST API and IP Cloud:

```bash
/ip service enable www-ssl
/ip service set [find name="www-ssl"] certificate=your-cert
/ip cloud set ddns-enabled=yes
```

## 🏗️ Build

```bash
dotnet restore
dotnet build -c Release
dotnet publish -c Release -r win-x64 --self-contained true
```

## 📦 Download

Pre-built self-contained binaries are available on the [Releases](https://github.com/thunder2004/DPI-Home/releases) page. No .NET runtime required — just extract and run.

## 📄 License

MIT