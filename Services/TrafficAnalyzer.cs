using System.Collections.Concurrent;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Анализатор трафика. Получает пакеты от парсера, прогоняет через сигнатуры и
/// поведенческие детекторы, генерирует алерты.
///
/// Исправления по сравнению с оригиналом:
///  - Направление трафика через NetworkContext (замена IsPrivateIp).
///  - Port Scan: только реальные пробы (SYN/stealth/UDP), не любой пакет.
///  - Brute Force: только SYN без ACK (активная сессия больше не триггерит).
///  - SYN Flood: ключ по ЖЕРТВЕ, считаем уникальные источники (поддержка спуфинга).
///  - Все состояния чистятся периодически (eviction), словари не растут бесконечно.
///  - Сигнатуры вынесены в ThreatSignatures, состояния — в DetectionState.
///  - Единая шкала Score через ThreatSignatures.ScoreFor.
///  - Рейт-лимит сигнатурных алертов: один алерт на (srcIp|sig) за 5 секунд.
///  - Фикс ошибки Now/UtcNow в очистке HTTPS-соединений.
/// </summary>
public class TrafficAnalyzer
{
    private readonly NetworkContext _net;
    private readonly List<ThreatSignature> _signatures;

    private readonly ConcurrentDictionary<string, PortScanState> _portScans = new();
    private readonly ConcurrentDictionary<string, BruteForceState> _bruteForce = new();
    private readonly ConcurrentDictionary<string, SynFloodState> _synFloods = new();
    private readonly ConcurrentDictionary<string, HttpsConnection> _httpsConnections = new();
    private readonly ConcurrentDictionary<string, HttpsServerGroup> _httpsServerGroups = new();
    private readonly object _httpsGroupLock = new();

    // Рейт-лимит: не чаще одного сигнатурного алерта на (srcIp|sig) за окно.
    private readonly ConcurrentDictionary<string, DateTime> _sigRateLimit = new();
    private static readonly TimeSpan SigRateLimitWindow = TimeSpan.FromSeconds(5);

    private const int PortScanThreshold = 20;
    private const int BruteForceThreshold = 10;
    private const int SynFloodThreshold = 100;
    private const int SynFloodSourceThreshold = 30; // уникальных источников — признак спуфинга
    private const int WindowSeconds = 10;

    // Нижняя граница эфемерного диапазона портов (RFC 6335 / большинство OC).
    // Реальный сканер, ищущий открытые сервисы у нас, никогда не пойдёт в этот
    // диапазон — там нет сервисов, только наши исходящие соединения. Без этого исключения
    // UDP-ответы от любого бустого сервиса (например, QUIC/HTTP3 от CDN на :443)
    // бьют в наши разные эфемерные порты и выглядит как «сканирование 20+ портов».
    private const int EphemeralPortMin = 49152;

    private DateTime _lastEviction = DateTime.UtcNow;
    private static readonly TimeSpan EvictionInterval = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan StateTtl = TimeSpan.FromMinutes(5);

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
        // Направление трафика — единожды, осознанно (заменяет IsPrivateIp).
        packet.Direction = _net.Classify(packet.SrcIp, packet.DstIp);

        bool relevant = packet.Direction is TrafficDirection.Inbound or TrafficDirection.Internal;

        if (relevant && packet.Protocol is "TCP" or "UDP" or "ICMP")
        {
            RunSignatures(packet);
            DetectPortScan(packet);
            DetectBruteForce(packet);
            DetectSynFlood(packet);
        }

        // HTTPS-трекинг ведём в обе стороны — иначе SYN-ACK не сопоставится.
        TrackHttpsConnection(packet);

        MaybeEvict();
    }

    // ── Сигнатурный анализ ──────────────────────────────────────────────────

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

    // ── Поведенческие детекторы ─────────────────────────────────────────────

    /// <summary>
    /// Port Scan: только реальные пробы.
    /// SYN без ACK, NULL/FIN/XMAS stealth, UDP-датаграммы — а не любой пакет.
    /// Это устраняет false positive от занятого CDN, отвечающего на 20+ наших портов.
    /// </summary>
    private void DetectPortScan(RawPacket packet)
    {
        if (string.IsNullOrEmpty(packet.SrcIp) || packet.DstPort == 0) return;
        if (packet.IsNonFirstFragment) return;

        // Порты в эфемерном диапазоне — это, как правило, НАШИ исходящие соединения,
        // а не сервисы, которые мог бы искать сканер. Ответный UDP-трафик от занятого
        // сервиса (QUIC/HTTP3, DNS-резолверы и т.д.) иначе даёт ложный port-скан.
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
                    Title = "Обнаружен порт-скан",
                    ShortName = "Port Scan",
                    Description = $"IP {packet.SrcIp}: {unique} уникальных портов за {WindowSeconds}с",
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
    /// Brute Force: только новые SYN (без ACK).
    /// Иначе любая активная SSH/RDP-сессия (10+ пакетов за 10с) = Critical false positive.
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
                    Title = $"Brute-force на {portName} (:{packet.DstPort})",
                    ShortName = $"BruteForce {portName}",
                    Description = $"IP {packet.SrcIp}: {state.InWindow(WindowSeconds)} попыток за {WindowSeconds}с на {portName}",
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
    /// SYN Flood: ключ — ЖЕРТВА (DstIp:DstPort), а не источник.
    /// Считаем уникальные источники: много источников = спуфинг-флуд.
    /// Раньше ключ был по SrcIp, который при спуфинге никогда не превышал порог.
    /// </summary>
    private void DetectSynFlood(RawPacket packet)
    {
        if (!packet.IsTcp || packet.DstPort == 0 || !packet.TcpFlagsParsed) return;
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
                    Title = $"SYN Flood на {packet.DstIp}:{packet.DstPort}",
                    ShortName = $"SYN Flood :{packet.DstPort}",
                    Description = spoofed
                        ? $"{syns} SYN/{WindowSeconds}с от {sources} источников (спуфинг) → {packet.DstIp}:{packet.DstPort}"
                        : $"{syns} SYN/{WindowSeconds}с от {sources} источников → {packet.DstIp}:{packet.DstPort}",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    DstPort = packet.DstPort,
                    Protocol = "TCP",
                    PacketCount = state.TotalSyns,
                    Score = ThreatSignatures.ScoreFor(ThreatLevel.Critical),
                    ScannedPorts = new HashSet<int> { packet.DstPort }
                });
                state.Reset();
            }
        }
    }

    // ── HTTPS-трекинг ───────────────────────────────────────────────────────

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
            // Используем UtcNow — согласовано с eviction-логикой (была ошибка Now vs UtcNow).
            var conn = _httpsConnections.GetOrAdd(connKey, _ => new HttpsConnection
            {
                Timestamp = DateTime.UtcNow,
                SrcIp = packet.SrcIp,
                DstIp = packet.DstIp,
                SrcPort = packet.SrcPort,
                DstPort = 443,
                State = ConnectionState.SynSent
            });
            conn.PacketCount++;
            conn.BytesTransferred += packet.PacketLength;
            OnHttpsConnectionUpdate?.Invoke(conn);
            UpdateHttpsServerGroup(serverIp);
        }
        else if (isSyn && isAck)
        {
            if (_httpsConnections.TryGetValue(connKey, out var conn))
            {
                conn.State = ConnectionState.Established;
                conn.PacketCount++;
                conn.BytesTransferred += packet.PacketLength;
                OnHttpsConnectionUpdate?.Invoke(conn);
                UpdateHttpsServerGroup(serverIp);
            }
        }
        else if (isRst || isFin)
        {
            if (_httpsConnections.TryGetValue(connKey, out var conn))
            {
                conn.State = ConnectionState.Closed;
                conn.Timestamp = DateTime.UtcNow;
                conn.PacketCount++;
                conn.BytesTransferred += packet.PacketLength;
                OnHttpsConnectionUpdate?.Invoke(conn);
                UpdateHttpsServerGroup(serverIp);
            }
        }
        else
        {
            if (_httpsConnections.TryGetValue(connKey, out var conn))
            {
                conn.PacketCount++;
                conn.BytesTransferred += packet.PacketLength;
                UpdateHttpsServerGroup(serverIp);
            }
        }

        if (_httpsConnections.Count > 5000)
        {
            var cutoff = DateTime.UtcNow.AddMinutes(-5);
            var cleanedServers = new HashSet<string>();
            foreach (var k in _httpsConnections.Keys)
            {
                if (_httpsConnections.TryGetValue(k, out var c) &&
                    c.State == ConnectionState.Closed && c.Timestamp < cutoff)
                {
                    cleanedServers.Add(c.SrcIp);
                    cleanedServers.Add(c.DstIp);
                    _httpsConnections.TryRemove(k, out _);
                }
            }
            foreach (var srv in cleanedServers)
                UpdateHttpsServerGroup(srv);
        }
    }

    private void UpdateHttpsServerGroup(string serverIp)
    {
        var group = _httpsServerGroups.GetOrAdd(serverIp, _ => new HttpsServerGroup
        {
            DstIp = serverIp,
            FirstSeen = DateTime.Now
        });

        lock (_httpsGroupLock)
        {
            group.LastSeen = DateTime.Now;
            var conns = _httpsConnections.Values
                .Where(c => c.DstIp == serverIp || c.SrcIp == serverIp)
                .ToList();

            group.TotalConnections = conns.Count;
            group.EstablishedCount = conns.Count(c => c.State == ConnectionState.Established);
            group.SynSentCount = conns.Count(c => c.State == ConnectionState.SynSent);
            group.ClosedCount = conns.Count(c => c.State == ConnectionState.Closed);
            group.TotalPackets = conns.Sum(c => c.PacketCount);
            group.TotalBytes = conns.Sum(c => c.BytesTransferred);
        }

        OnHttpsServerGroupUpdate?.Invoke(group);
    }

    // ── Eviction — периодическая чистка протухших состояний ────────────────

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

        var rlCutoff = now - StateTtl;
        foreach (var kv in _sigRateLimit)
            if (kv.Value < rlCutoff) _sigRateLimit.TryRemove(kv.Key, out _);

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
