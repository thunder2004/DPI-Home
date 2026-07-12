using System.Collections.Concurrent;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Traffic analyzer. Receives packets from the parser, runs them through signatures
/// and behavioral detectors, generates alerts.
///
/// Improvements over the original:
///  - Traffic direction via NetworkContext (replaces IsPrivateIp).
///  - Port Scan: only real probes (SYN/stealth/UDP), not any packet; ephemeral
///    ports (>=49152) excluded — otherwise reply UDP traffic (QUIC/HTTP3) from a busy
///    CDN gives a false "scan" of our own random outgoing ports.
///  - Brute Force: only SYN without ACK (active session no longer triggers).
///  - SYN Flood: key by VICTIM, count unique sources (spoofing support).
///  - All states are periodically evicted, dictionaries don't grow indefinitely.
///  - Signatures moved to ThreatSignatures, states to DetectionState.
///  - Unified Score scale via ThreatSignatures.ScoreFor.
///  - Rate-limit signature alerts: one alert per (srcIp|sig) per 5 seconds.
///  - Fixed Now/UtcNow bug in HTTPS connection cleanup.
///  - HTTPS server group: incremental counters (O(1) per packet), UI event
///    throttled 300ms/server — previously a full LINQ scan of all connections on EVERY
///    443-port packet + synchronous Dispatcher.Invoke per call caused multi-second
///    UI freezes under real load (HTTPS/QUIC is the majority of traffic).
/// </summary>
public class TrafficAnalyzer
{
    private readonly NetworkContext _net;
    private readonly List<ThreatSignature> _signatures;

    private TrafficStats _stats = new();

    private readonly ConcurrentDictionary<string, PortScanState> _portScans = new();
    private readonly ConcurrentDictionary<string, BruteForceState> _bruteForce = new();
    private readonly ConcurrentDictionary<string, SynFloodState> _synFloods = new();
    private readonly ConcurrentDictionary<string, RdpAuthState> _rdpAuth = new();
    private readonly ConcurrentDictionary<string, HttpsConnection> _httpsConnections = new();
    private readonly ConcurrentDictionary<string, HttpsServerGroup> _httpsServerGroups = new();
    private readonly object _httpsGroupLock = new();

    // Rate-limit: at most one signature alert per (srcIp|sig) per window.
    private readonly ConcurrentDictionary<string, DateTime> _sigRateLimit = new();
    private static readonly TimeSpan SigRateLimitWindow = TimeSpan.FromSeconds(5);

    // Throttle HTTPS-group UI event: previously UpdateHttpsServerGroup was called
    // (and synchronously blocked UI via Dispatcher.Invoke) on EVERY 443-port packet —
    // under real traffic (HTTPS/QUIC is the majority of all traffic) this meant thousands
    // of calls per second with full O(n) dictionary scan, causing UI freezes.
    private readonly ConcurrentDictionary<string, DateTime> _httpsGroupLastEmit = new();
    private static readonly TimeSpan HttpsGroupEmitInterval = TimeSpan.FromMilliseconds(300);

    private const int PortScanThreshold = 20;
    private const int BruteForceThreshold = 10;
    private const int SynFloodThreshold = 100;
    private const int SynFloodSourceThreshold = 30; // unique sources — spoofing indicator
    public int RdpThreshold { get; set; } = 3;
    public int RdpWindowSeconds { get; set; } = 300;

    /// <summary>
    /// Ports excluded from SYN Flood / Port Scan detection — e.g. a torrent client's
    /// listening port. Legitimate swarm traffic (many short-lived connections from
    /// many different real peer IPs, all hitting one fixed local port) is
    /// numerically indistinguishable from a SYN flood; the only reliable way to tell
    /// them apart is knowing which ports are expected to behave that way.
    /// </summary>
    public HashSet<int> ExcludedPorts { get; set; } = new();

    private const int WindowSeconds = 10;

    // Lower bound of the ephemeral port range (RFC 6335 / most OSes).
    // A real scanner looking for open services on our host would never go into this
    // range — there are no services there, only our outgoing connections.
    private const int EphemeralPortMin = 49152;

    private DateTime _lastEviction = DateTime.UtcNow;
    private static readonly TimeSpan EvictionInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan StateTtl = TimeSpan.FromMinutes(5);

    public event Action<string>? OnDebugLog;
    public event Action<Alert>? OnAlert;
    public event Action<HttpsConnection>? OnHttpsConnectionUpdate;
    public event Action<HttpsServerGroup>? OnHttpsServerGroupUpdate;

    public IReadOnlyCollection<HttpsConnection> HttpsConnections =>
        _httpsConnections.Values.ToList().AsReadOnly();

    public TrafficAnalyzer(NetworkContext? net = null)
    {
        _net = net ?? NetworkContext.CreateDefault();
        _signatures = ThreatSignatures.LoadAll();
    }

    public void Analyze(RawPacket packet)
    {
        if (packet == null) return;

        _stats.TotalPackets++;
        
        // Debug: log incoming packets every 100
        if (_stats.TotalPackets % 100 == 0)
            OnDebugLog?.Invoke($"[PKT] Total: {_stats.TotalPackets} | Last: {packet.Protocol} {packet.SrcIp}→{packet.DstIp}:{packet.DstPort} Dir:{packet.Direction}");

        // Traffic direction — once, deliberately (replaces IsPrivateIp).
        packet.Direction = _net.Classify(packet.SrcIp, packet.DstIp);

        // note: skip all detectors for well-known service IPs (Google DNS, Apple DNS,
        // Cloudflare, etc.) — they trigger false DNS/ICMP tunneling and port scan alerts.
        // Alerts are noise; auto-block was already suppressed, but the alerts flooded the UI.
        if (_net.IsWellKnown(packet.SrcIp) || _net.IsWellKnown(packet.DstIp))
        {
            TrackHttpsConnection(packet);
            MaybeEvict();
            return;
        }

        bool relevant = packet.Direction is TrafficDirection.Inbound or TrafficDirection.Internal;

        if (relevant && (packet.Protocol is "TCP" or "UDP" or "ICMP"))
        {
            // NOTE: RunSignatures (NULL/FIN/XMAS scan, EternalBlue, DNS/ICMP tunneling)
            // and DetectPortScan were missing from this block — a prior edit added
            // DetectRdpBruteForce/well-known-IP suppression but dropped these two calls,
            // silently disabling port scan detection and all signature-based alerts.
            RunSignatures(packet);
            DetectPortScan(packet);
            DetectBruteForce(packet);
            DetectSynFlood(packet);
            DetectRdpBruteForce(packet);
        }

        // HTTPS tracking in both directions — otherwise SYN-ACK won't match.
        TrackHttpsConnection(packet);

        MaybeEvict();
    }

    // ── Signature analysis ──────────────────────────────────────────────────

    private void RunSignatures(RawPacket packet)
    {
        foreach (var sig in _signatures)
        {
            if (!sig.Match(packet)) continue;
            if (IsSigRateLimited(packet.SrcIp, sig.Name)) continue;

            EmitAlert(new Alert
            {
                Timestamp = DateTime.Now,
                Level = sig.Level,
                Category = sig.Category,
                Title = sig.Name,
                ShortName = sig.Name,
                Description = sig.Description,
                SrcIp = packet.SrcIp,
                DstIp = packet.DstIp,
                SrcPort = packet.SrcPort,
                DstPort = packet.DstPort,
                Protocol = packet.Protocol,
                PacketCount = 1,
                Score = ThreatSignatures.ScoreFor(sig.Level),
                ScannedPorts = packet.DstPort > 0 ? new HashSet<int> { packet.DstPort } : new()
            });
        }
    }

    private bool IsSigRateLimited(string srcIp, string sigName)
    {
        var key = $"{srcIp}|{sigName}";
        var now = DateTime.UtcNow;
        if (_sigRateLimit.TryGetValue(key, out var last) && now - last < SigRateLimitWindow)
            return true;
        _sigRateLimit[key] = now;
        return false;
    }

    // ── Behavioral detectors ────────────────────────────────────────────────

    /// <summary>
    /// Port Scan: only real probes.
    /// SYN without ACK, NULL/FIN/XMAS stealth, UDP datagrams — not any packet.
    /// This eliminates false positives from a busy CDN replying to 20+ of our ports.
    /// </summary>
    private void DetectPortScan(RawPacket packet)
    {
        if (string.IsNullOrEmpty(packet.SrcIp) || packet.DstPort == 0) return;
        if (packet.IsNonFirstFragment) return;
        if (ExcludedPorts.Contains(packet.DstPort)) return;

        // Ports in the ephemeral range are typically OUR outgoing connections,
        // not services a scanner would look for. Reply UDP traffic from a busy
        // service (QUIC/HTTP3, DNS resolvers, etc.) otherwise gives a false port-scan.
        if (packet.DstPort >= EphemeralPortMin) return;

        bool isProbe;
        if (packet.IsTcp && packet.TcpFlagsParsed)
        {
            bool syn = (packet.TcpFlags & 0x02) != 0;
            bool ack = (packet.TcpFlags & 0x10) != 0;
            bool stealth = packet.TcpFlags == 0x00
                        || (packet.TcpFlags & 0x3F) == 0x01
                        || ((packet.TcpFlags & 0x29) == 0x29 && (packet.TcpFlags & 0x14) == 0);
            isProbe = (syn && !ack) || stealth;
        }
        else if (packet.IsUdp)
        {
            isProbe = true;
        }
        else return;

        if (!isProbe) return;

        var state = _portScans.GetOrAdd(packet.SrcIp, _ => new PortScanState());
        lock (state)
        {
            state.Purge(WindowSeconds);
            state.AddProbe(packet.DstPort, packet.Timestamp);
            int unique = state.UniquePorts(WindowSeconds);
            if (unique >= PortScanThreshold)
            {
                EmitAlert(new Alert
                {
                    Timestamp = DateTime.Now,
                    Level = ThreatLevel.High,
                    Category = "Port Scan",
                    Title = "Port scan detected",
                    ShortName = "Port Scan",
                    Description = $"IP {packet.SrcIp}: {unique} unique ports in {WindowSeconds}s",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    Protocol = packet.Protocol,
                    PacketCount = state.TotalProbes,
                    Score = ThreatSignatures.ScoreFor(ThreatLevel.High),
                    ScannedPorts = state.Ports(WindowSeconds)
                });
                state.Reset();
            }
        }
    }

    /// <summary>
    /// Brute Force: only new SYN (without ACK).
    /// Otherwise any active SSH/RDP session (10+ packets in 10s) = Critical false positive.
    /// </summary>
    private void DetectBruteForce(RawPacket packet)
    {
        if (string.IsNullOrEmpty(packet.SrcIp) || packet.DstPort == 0) return;
        if (!packet.IsTcp || !packet.TcpFlagsParsed) return;
        if (packet.DstPort is not (22 or 3389 or 21 or 1433 or 3306 or 5432)) return;

        bool isSyn = (packet.TcpFlags & 0x02) != 0;
        bool isAck = (packet.TcpFlags & 0x10) != 0;
        if (!(isSyn && !isAck)) return;

        var key = $"{packet.SrcIp}:{packet.DstPort}";
        var state = _bruteForce.GetOrAdd(key, _ => new BruteForceState());
        lock (state)
        {
            state.Purge(WindowSeconds);
            state.AddAttempt(packet.Timestamp);
            if (state.InWindow(WindowSeconds) >= BruteForceThreshold)
            {
                string portName = packet.DstPort switch
                {
                    22 => "SSH", 3389 => "RDP", 21 => "FTP",
                    1433 => "MSSQL", 3306 => "MySQL", 5432 => "PostgreSQL",
                    _ => $"{packet.DstPort}"
                };
                EmitAlert(new Alert
                {
                    Timestamp = DateTime.Now,
                    Level = ThreatLevel.Critical,
                    Category = "Brute Force",
                    Title = $"Brute-force on {portName} (:{packet.DstPort})",
                    ShortName = $"BruteForce {portName}",
                    Description = $"IP {packet.SrcIp}: {state.InWindow(WindowSeconds)} attempts in {WindowSeconds}s on {portName}",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    DstPort = packet.DstPort,
                    Protocol = packet.Protocol,
                    PacketCount = state.TotalAttempts,
                    Score = ThreatSignatures.ScoreFor(ThreatLevel.Critical),
                    ScannedPorts = new HashSet<int> { packet.DstPort }
                });
                state.Reset();
            }
        }
    }

    /// <summary>
    /// SYN Flood: key is the VICTIM (DstIp:DstPort), not the source.
    /// Count unique sources: many sources = spoofed flood.
    /// Previously the key was by SrcIp, which under spoofing never exceeded the threshold.
    /// </summary>
    private void DetectSynFlood(RawPacket packet)
    {
        if (!packet.IsTcp || packet.DstPort == 0 || !packet.TcpFlagsParsed) return;
        if (ExcludedPorts.Contains(packet.DstPort)) return;
        bool isSyn = (packet.TcpFlags & 0x02) != 0;
        bool isAck = (packet.TcpFlags & 0x10) != 0;
        if (!isSyn || isAck) return;

        var key = $"{packet.DstIp}:{packet.DstPort}";
        var state = _synFloods.GetOrAdd(key, _ => new SynFloodState());
        lock (state)
        {
            state.Purge(WindowSeconds);
            state.AddSyn(packet.SrcIp, packet.Timestamp);

            int syns = state.InWindow(WindowSeconds);
            int sources = state.UniqueSources(WindowSeconds);

            if (syns >= SynFloodThreshold)
            {
                bool spoofed = sources >= SynFloodSourceThreshold;
                EmitAlert(new Alert
                {
                    Timestamp = DateTime.Now,
                    Level = ThreatLevel.Critical,
                    Category = "SYN Flood",
                    Title = $"SYN Flood on {packet.DstIp}:{packet.DstPort}",
                    ShortName = $"SYN Flood :{packet.DstPort}",
                    Description = spoofed
                        ? $"{syns} SYN/{WindowSeconds}s from {sources} sources (spoofed) → {packet.DstIp}:{packet.DstPort}"
                        : $"{syns} SYN/{WindowSeconds}s from {sources} sources → {packet.DstIp}:{packet.DstPort}",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    DstPort = packet.DstPort,
                    Protocol = "TCP",
                    PacketCount = state.TotalSyns,
                    Score = ThreatSignatures.ScoreFor(ThreatLevel.Critical),
                    ScannedPorts = new HashSet<int> { packet.DstPort },
                    Spoofed = spoofed
                });
                state.Reset();
            }
        }
    }

    // ── HTTPS tracking ───────────────────────────────────────────────────────

    /// <summary>
    /// RDP Brute Force: 3 new TCP connections (SYN without ACK) to port 3389
    /// from one SrcIp in 5 minutes. Window is wider than other detectors because
    /// an attacker usually doesn't spam SYN-flood, but methodically guesses passwords.
    /// Level Critical — blocked by auto-block (if enabled).
    /// </summary>
    private void DetectRdpBruteForce(RawPacket packet)
    {
        if (!packet.IsTcp || !packet.TcpFlagsParsed) return;
        if (packet.DstPort != 3389) return;

        bool isSyn = (packet.TcpFlags & 0x02) != 0;
        bool isAck = (packet.TcpFlags & 0x10) != 0;
        if (!isSyn || isAck) return; // only new connections

        var key = packet.SrcIp;
        var state = _rdpAuth.GetOrAdd(key, _ => new RdpAuthState());
        lock (state)
        {
            state.Purge(RdpWindowSeconds);
            state.AddAttempt(packet.Timestamp);
            int count = state.InWindow(RdpWindowSeconds);

            if (count >= RdpThreshold)
            {
                EmitAlert(new Alert
                {
                    Timestamp = DateTime.Now,
                    Level = ThreatLevel.Critical,
                    Category = "RDP Brute Force",
                    Title = $"RDP password brute-force from {packet.SrcIp}",
                    ShortName = "RDP BruteForce",
                    Description = $"IP {packet.SrcIp}: {count} connection attempts to RDP (3389) in {RdpWindowSeconds / 60} min",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    DstPort = 3389,
                    Protocol = "TCP",
                    PacketCount = state.TotalAttempts,
                    Score = ThreatSignatures.ScoreFor(ThreatLevel.Critical),
                    ScannedPorts = new HashSet<int> { 3389 }
                });
                state.Reset();
            }
        }
    }

    /// <summary>
    /// Group counters are incremented per packet (O(1)),
    /// not recalculated by a full scan of all connections (was O(n) per packet).
    /// </summary>
    private void TrackHttpsConnection(RawPacket packet)
    {
        if (!packet.IsTcp || !packet.TcpFlagsParsed) return;
        if (packet.DstPort != 443 && packet.SrcPort != 443) return;

        bool isSyn = (packet.TcpFlags & 0x02) != 0;
        bool isAck = (packet.TcpFlags & 0x10) != 0;
        bool isRst = (packet.TcpFlags & 0x04) != 0;
        bool isFin = (packet.TcpFlags & 0x01) != 0;

        string clientIp, serverIp;
        int clientPort;
        if (packet.DstPort == 443)
        {
            clientIp = packet.SrcIp; clientPort = packet.SrcPort; serverIp = packet.DstIp;
        }
        else
        {
            clientIp = packet.DstIp; clientPort = packet.DstPort; serverIp = packet.SrcIp;
        }

        var connKey = $"{clientIp}:{clientPort}->{serverIp}:443";

        if (isSyn && !isAck)
        {
            // Important: the "HTTPS connections" panel must show only inbound connections
            // (someone from WAN knocking on our service on 443), NOT our own
            // outgoing connections (browser → CDN/sites). The direction of this
            // first SYN packet unambiguously says who the initiator is: Outbound = us as client,
            // Inbound = someone outside opening a connection to us. Without this check,
            // our own internet traffic also ended up here (e.g. Cloudflare from QUIC/HTTPS browsing).
            if (packet.Direction != TrafficDirection.Inbound) return;

            bool isNew = false;
            var conn = _httpsConnections.GetOrAdd(connKey, _ =>
            {
                isNew = true;
                return new HttpsConnection
                {
                    Timestamp = DateTime.UtcNow, // consistent with eviction logic (was Now vs UtcNow bug)
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    SrcPort = packet.SrcPort,
                    DstPort = 443,
                    ServerIp = serverIp,
                    ClientIp = clientIp,
                    State = ConnectionState.SynSent
                };
            });
            conn.PacketCount++;
            conn.BytesTransferred += packet.PacketLength;

            // Group by CLIENT, not server: after the "inbound only" filter,
            // server always equals our own WAN-IP, so grouping by it
            // would collapse all different attackers into one line with our address.
            if (isNew)
                AdjustClientGroup(clientIp, g => { g.SynSentCount++; g.TotalConnections++; });
            else
                AdjustClientGroup(clientIp, _ => { }); // SYN retransmit — state counters don't change

            OnHttpsConnectionUpdate?.Invoke(conn);
        }
        else if (isSyn && isAck)
        {
            if (_httpsConnections.TryGetValue(connKey, out var conn) && conn.State == ConnectionState.SynSent)
            {
                conn.State = ConnectionState.Established;
                conn.PacketCount++;
                conn.BytesTransferred += packet.PacketLength;
                AdjustClientGroup(clientIp, g => { g.SynSentCount--; g.EstablishedCount++; });
                OnHttpsConnectionUpdate?.Invoke(conn);
            }
        }
        else if (isRst || isFin)
        {
            if (_httpsConnections.TryGetValue(connKey, out var conn) && conn.State != ConnectionState.Closed)
            {
                var prevState = conn.State;
                conn.State = ConnectionState.Closed;
                conn.Timestamp = DateTime.UtcNow; // close time — for TTL during eviction
                conn.PacketCount++;
                conn.BytesTransferred += packet.PacketLength;
                AdjustClientGroup(clientIp, g =>
                {
                    if (prevState == ConnectionState.Established) g.EstablishedCount--;
                    else if (prevState == ConnectionState.SynSent) g.SynSentCount--;
                    g.ClosedCount++;
                });
                OnHttpsConnectionUpdate?.Invoke(conn);
            }
        }
        else
        {
            // Regular data packet within an existing connection — the most common event
            // under real load. State counters don't change, so we update
            // only LastSeen via a throttled emit, without rescanning the whole dictionary.
            if (_httpsConnections.TryGetValue(connKey, out var conn))
            {
                conn.PacketCount++;
                conn.BytesTransferred += packet.PacketLength;
                AdjustClientGroup(clientIp, _ => { });
            }
        }

        if (_httpsConnections.Count > 5000)
            EvictClosedHttpsConnections();
    }

    /// <summary>Selectively evicts closed connections older than 5 minutes, decrementing group counters.</summary>
    private void EvictClosedHttpsConnections()
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-5);
        foreach (var k in _httpsConnections.Keys)
        {
            if (_httpsConnections.TryGetValue(k, out var c) &&
                c.State == ConnectionState.Closed && c.Timestamp < cutoff &&
                _httpsConnections.TryRemove(k, out var removed))
            {
                AdjustClientGroup(removed.ClientIp, g =>
                {
                    g.ClosedCount = Math.Max(0, g.ClosedCount - 1);
                    g.TotalConnections = Math.Max(0, g.TotalConnections - 1);
                    g.TotalPackets = Math.Max(0, g.TotalPackets - removed.PacketCount);
                    g.TotalBytes = Math.Max(0, g.TotalBytes - removed.BytesTransferred);
                });
            }
        }
    }

    /// <summary>
    /// Mutates the per-CLIENT group (external IP connecting to us) and emits a
    /// UI event throttled at 300ms per client — the counter mutation is always O(1)
    /// and unlimited, only the UI redraw is throttled.
    /// </summary>
    private void AdjustClientGroup(string clientIp, Action<HttpsServerGroup> mutate)
    {
        var group = _httpsServerGroups.GetOrAdd(clientIp, _ => new HttpsServerGroup
        {
            DstIp = clientIp,
            FirstSeen = DateTime.Now
        });

        lock (_httpsGroupLock)
        {
            group.LastSeen = DateTime.Now;
            mutate(group);
        }

        var now = DateTime.UtcNow;
        bool shouldEmit = !_httpsGroupLastEmit.TryGetValue(clientIp, out var last)
                        || now - last >= HttpsGroupEmitInterval;
        if (shouldEmit)
        {
            _httpsGroupLastEmit[clientIp] = now;
            OnHttpsServerGroupUpdate?.Invoke(group);
        }
    }

    // ── Eviction — periodic cleanup of stale states ────────────────

    private void MaybeEvict()
    {
        var now = DateTime.UtcNow;
        if (now - _lastEviction < EvictionInterval) return;
        _lastEviction = now;

        foreach (var kv in _portScans)
            if (kv.Value.IsStale(StateTtl)) _portScans.TryRemove(kv.Key, out _);

        foreach (var kv in _bruteForce)
            if (kv.Value.IsStale(StateTtl)) _bruteForce.TryRemove(kv.Key, out _);

        foreach (var kv in _synFloods)
            if (kv.Value.IsStale(StateTtl)) _synFloods.TryRemove(kv.Key, out _);

        foreach (var kv in _rdpAuth)
            if (kv.Value.IsStale(StateTtl)) _rdpAuth.TryRemove(kv.Key, out _);

        var rlCutoff = now - StateTtl;
        foreach (var kv in _sigRateLimit)
            if (kv.Value < rlCutoff) _sigRateLimit.TryRemove(kv.Key, out _);

        var emitCutoff = now - StateTtl;
        foreach (var kv in _httpsGroupLastEmit)
            if (kv.Value < emitCutoff) _httpsGroupLastEmit.TryRemove(kv.Key, out _);

        foreach (var kv in _httpsServerGroups)
        {
            var g = kv.Value;
            if (g.EstablishedCount == 0 && g.SynSentCount == 0 &&
                (now - g.LastSeen.ToUniversalTime()) > StateTtl)
                _httpsServerGroups.TryRemove(kv.Key, out _);
        }
    }

    private void EmitAlert(Alert alert) => OnAlert?.Invoke(alert);
}