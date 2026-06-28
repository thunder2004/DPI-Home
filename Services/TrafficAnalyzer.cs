using System.Collections.Concurrent;
using DPI_Home.Models;

namespace DPI_Home.Services;

public record ThreatSignature
{
    public string Name { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public ThreatLevel Level { get; init; } = ThreatLevel.Medium;
    public string Description { get; init; } = string.Empty;
    public Func<RawPacket, bool> Match { get; init; } = _ => false;
}

public class TrafficAnalyzer
{
    private readonly List<ThreatSignature> _signatures;
    private readonly ConcurrentDictionary<string, PortScanState> _portScans = new();
    private readonly ConcurrentDictionary<string, BruteForceState> _bruteForce = new();
    private readonly ConcurrentDictionary<string, SynFloodState> _synFloods = new();
    private readonly ConcurrentDictionary<string, HttpsConnection> _httpsConnections = new();
    private readonly ConcurrentDictionary<string, HttpsServerGroup> _httpsServerGroups = new();
    private readonly object _httpsGroupLock = new();

    private const int PortScanThreshold = 20;    // уникальных портов за WindowSeconds
    private const int BruteForceThreshold = 10;  // новых попыток соединения (SYN) за WindowSeconds
    private const int SynFloodThreshold = 100;   // SYN-пакетов за WindowSeconds
    private const int WindowSeconds = 10;

    public event Action<Alert>? OnAlert;
    public event Action<HttpsConnection>? OnHttpsConnectionUpdate;
    public event Action<HttpsServerGroup>? OnHttpsServerGroupUpdate;

    public IReadOnlyCollection<HttpsConnection> HttpsConnections =>
        _httpsConnections.Values.ToList().AsReadOnly();

    public TrafficAnalyzer() => _signatures = LoadSignatures();

    /// <summary>
    /// Проверяет, является ли IP локальным (RFC 1918 + link-local + loopback).
    /// Пакеты от таких IP в контексте WAN rx — это NAT-reflection или артефакты RouterOS.
    /// </summary>
    private static bool IsPrivateIp(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return false;
        if (ip.StartsWith("10.")) return true;
        if (ip.StartsWith("192.168.")) return true;
        if (ip.StartsWith("127.")) return true;
        if (ip.StartsWith("169.254.")) return true;
        if (ip.StartsWith("172."))
        {
            var dotIdx = ip.IndexOf('.', 4);
            if (dotIdx > 4 && int.TryParse(ip.AsSpan(4, dotIdx - 4), out int second) && second >= 16 && second <= 31)
                return true;
        }
        return false;
    }

    /// <summary>
    /// Возвращает true если TCP-флаги были реально считаны (пакет не truncated).
    /// Пакет с TcpFlagsParsed=false не может использоваться для сигнатур на флаги.
    /// </summary>
    private static bool IsTcpFlagsParsed(RawPacket p)
        => p.TcpFlagsParsed;

    public void Analyze(RawPacket packet)
    {
        // Игнорируем локальные IP — NAT-reflection и артефакты RouterOS на WAN rx
        if (IsPrivateIp(packet.SrcIp))
            return;

        // Сигнатурный анализ
        foreach (var sig in _signatures)
        {
            if (sig.Match(packet))
            {
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
                    Score = (int)sig.Level * 25,
                    ScannedPorts = packet.DstPort > 0 ? new HashSet<int> { packet.DstPort } : new()
                });
            }
        }

        DetectPortScan(packet);
        DetectBruteForce(packet);
        DetectSynFlood(packet);
        TrackHttpsConnection(packet);
    }

    private void DetectPortScan(RawPacket packet)
    {
        if (string.IsNullOrEmpty(packet.SrcIp) || packet.DstPort == 0) return;

        var state = _portScans.GetOrAdd(packet.SrcIp, _ => new PortScanState());
        lock (state)
        {
            state.PurgeOld(WindowSeconds);
            state.AddAttempt(packet.DstPort, packet.Timestamp);
            int uniquePorts = state.UniquePortsInWindow(WindowSeconds);
            if (uniquePorts >= PortScanThreshold)
            {
                EmitAlert(new Alert
                {
                    Timestamp = DateTime.Now,
                    Level = ThreatLevel.High,
                    Category = "Port Scan",
                    Title = "Обнаружен порт-скан",
                    ShortName = "Port Scan",
                    Description = $"IP {packet.SrcIp} сканирует порты: {uniquePorts} уникальных портов за {WindowSeconds}с",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    Protocol = packet.Protocol,
                    PacketCount = state.TotalAttempts,
                    Score = 75,
                    ScannedPorts = new HashSet<int>(state.GetPortsInWindow(WindowSeconds))
                });
                state.Reset();
            }
        }
    }

    private void DetectBruteForce(RawPacket packet)
    {
        if (string.IsNullOrEmpty(packet.SrcIp) || packet.DstPort == 0) return;
        if (packet.DstPort is not (22 or 3389 or 21 or 1433 or 3306 or 5432)) return;

        // ── FIX: считаем только новые соединения (SYN без ACK), не все пакеты ──
        // Без этого любая активная SSH/RDP-сессия (10+ пакетов за 10с) даёт false positive
        bool isSyn = (packet.TcpFlags & 0x02) != 0;
        bool isAck = (packet.TcpFlags & 0x10) != 0;
        if (!(isSyn && !isAck)) return;

        var key = $"{packet.SrcIp}:{packet.DstPort}";
        var state = _bruteForce.GetOrAdd(key, _ => new BruteForceState());
        lock (state)
        {
            state.PurgeOld(WindowSeconds);
            state.AddAttempt(packet.Timestamp);
            if (state.AttemptsInWindow(WindowSeconds) >= BruteForceThreshold)
            {
                string portName = packet.DstPort switch
                {
                    22 => "SSH",
                    3389 => "RDP",
                    21 => "FTP",
                    1433 => "MSSQL",
                    3306 => "MySQL",
                    5432 => "PostgreSQL",
                    _ => $"{packet.DstPort}"
                };
                EmitAlert(new Alert
                {
                    Timestamp = DateTime.Now,
                    Level = ThreatLevel.Critical,
                    Category = "Brute Force",
                    Title = $"Brute-force на {portName} (:{packet.DstPort})",
                    ShortName = $"BruteForce {portName}",
                    Description = $"IP {packet.SrcIp} — {state.AttemptsInWindow(WindowSeconds)} попыток подключения за {WindowSeconds}с на {portName}",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    DstPort = packet.DstPort,
                    Protocol = packet.Protocol,
                    PacketCount = state.TotalAttempts,
                    Score = 90,
                    ScannedPorts = new HashSet<int> { packet.DstPort }
                });
                state.Reset();
            }
        }
    }

    private void DetectSynFlood(RawPacket packet)
    {
        // ── FIX: детектируем SYN flood на ВСЕХ TCP-портах, не только 443 ──
        if (packet.Protocol != "TCP" || packet.DstPort == 0) return;
        bool isSyn = (packet.TcpFlags & 0x02) != 0;
        bool isAck = (packet.TcpFlags & 0x10) != 0;
        if (!isSyn || isAck) return;

        // Ключ по IP+порт: отдельное состояние для каждого атакуемого порта
        var key = $"{packet.SrcIp}:{packet.DstPort}";
        var state = _synFloods.GetOrAdd(key, _ => new SynFloodState());
        lock (state)
        {
            state.PurgeOld(WindowSeconds);
            state.AddAttempt(packet.Timestamp);
            if (state.AttemptsInWindow(WindowSeconds) >= SynFloodThreshold)
            {
                EmitAlert(new Alert
                {
                    Timestamp = DateTime.Now,
                    Level = ThreatLevel.Critical,
                    Category = "SYN Flood",
                    Title = $"SYN Flood на порт {packet.DstPort}",
                    ShortName = $"SYN Flood :{packet.DstPort}",
                    Description = $"IP {packet.SrcIp} — {state.AttemptsInWindow(WindowSeconds)} SYN-пакетов за {WindowSeconds}с на порт {packet.DstPort}",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    DstPort = packet.DstPort,
                    Protocol = "TCP",
                    PacketCount = state.TotalAttempts,
                    Score = 95,
                    ScannedPorts = new HashSet<int> { packet.DstPort }
                });
                state.Reset();
            }
        }
    }

    private void TrackHttpsConnection(RawPacket packet)
    {
        if (packet.Protocol != "TCP") return;
        if (packet.DstPort != 443 && packet.SrcPort != 443) return;

        bool isSyn = (packet.TcpFlags & 0x02) != 0;
        bool isAck = (packet.TcpFlags & 0x10) != 0;
        bool isRst = (packet.TcpFlags & 0x04) != 0;
        bool isFin = (packet.TcpFlags & 0x01) != 0;

        string clientIp, serverIp;
        int clientPort;

        if (packet.DstPort == 443)
        {
            clientIp = packet.SrcIp;
            clientPort = packet.SrcPort;
            serverIp = packet.DstIp;
        }
        else
        {
            clientIp = packet.DstIp;
            clientPort = packet.DstPort;
            serverIp = packet.SrcIp;
        }

        var connKey = $"{clientIp}:{clientPort}->{serverIp}:443";

        if (isSyn && !isAck)
        {
            var conn = _httpsConnections.GetOrAdd(connKey, _ => new HttpsConnection
            {
                Timestamp = DateTime.Now,
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
                    c.State == ConnectionState.Closed &&
                    c.Timestamp < cutoff)
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
            var connectionsToServer = _httpsConnections.Values
                .Where(c => c.DstIp == serverIp || c.SrcIp == serverIp)
                .ToList();

            group.TotalConnections = connectionsToServer.Count;
            group.EstablishedCount = connectionsToServer.Count(c => c.State == ConnectionState.Established);
            group.SynSentCount = connectionsToServer.Count(c => c.State == ConnectionState.SynSent);
            group.ClosedCount = connectionsToServer.Count(c => c.State == ConnectionState.Closed);
            group.TotalPackets = connectionsToServer.Sum(c => c.PacketCount);
            group.TotalBytes = connectionsToServer.Sum(c => c.BytesTransferred);
        }

        OnHttpsServerGroupUpdate?.Invoke(group);
    }

    private void EmitAlert(Alert alert) => OnAlert?.Invoke(alert);

    private static List<ThreatSignature> LoadSignatures() => new()
    {
        // ─── TCP Scan Signatures — используем TcpFlags + TcpFlagsParsed ───

        // NULL Scan: все флаги нулевые. Только если флаги были реально считаны из пакета.
        new() { Name = "NULL Scan", Category = "Recon", Level = ThreatLevel.High,
            Description = "TCP NULL Scan — пакет без каких-либо флагов (FIN/SYN/RST/PSH/ACK/URG=0)",
            Match = p => p.Protocol == "TCP" && p.TcpFlagsParsed && p.TcpFlags == 0x00 && p.DstPort > 0 },

        // XMAS Scan: FIN(1)+PSH(8)+URG(32)=0x29, без SYN и ACK
        new() { Name = "XMAS Scan", Category = "Recon", Level = ThreatLevel.High,
            Description = "TCP XMAS Scan — одновременно установлены FIN+PSH+URG флаги",
            Match = p => p.Protocol == "TCP" && p.TcpFlagsParsed && (p.TcpFlags & 0x29) == 0x29 && (p.TcpFlags & 0x12) == 0 },

        // FIN Scan: только FIN, без других флагов
        new() { Name = "FIN Scan", Category = "Recon", Level = ThreatLevel.Medium,
            Description = "TCP FIN Scan — только FIN флаг, без SYN/ACK/RST",
            Match = p => p.Protocol == "TCP" && p.TcpFlagsParsed && (p.TcpFlags & 0x3F) == 0x01 },

        // ─── Exploit Signatures ───

        // EternalBlue: SMB1 magic \xFF SMB в первых 128 байтах payload
        // FIX: проверяем PayloadRaw напрямую, не обрезанный PayloadHex
        new() { Name = "EternalBlue", Category = "Exploit", Level = ThreatLevel.Critical,
            Description = "EternalBlue/MS17-010 — SMB1 эксплойт на порт 445",
            Match = p => p.DstPort == 445 && p.PayloadRaw.Length > 60 &&
                         ContainsBytes(p.PayloadRaw, new byte[] { 0xFF, 0x53, 0x4D, 0x42 }) },  // \xFFSMB

        // ─── C2/Tunnel Signatures ───

        // DNS Tunneling: только UDP DNS > 512 байт (TCP DNS — норма для zone transfer / DNSSEC)
        new() { Name = "DNS Tunneling", Category = "C2/Tunnel", Level = ThreatLevel.High,
            Description = "UDP DNS-запрос > 512 байт — возможный DNS-туннель (EDNS0 limit)",
            Match = p => p.DstPort == 53 && p.Protocol == "UDP" && p.PacketLength > 512 },

        // ICMP Tunneling: payload > 1000 байт — аномальный ICMP
        new() { Name = "ICMP Tunneling", Category = "C2/Tunnel", Level = ThreatLevel.High,
            Description = "Аномально большой ICMP-пакет (>1000 байт) — возможный туннель",
            Match = p => p.Protocol == "ICMP" && p.PacketLength > 1000 },
    };

    /// <summary>
    /// Поиск последовательности байт в массиве (аналог Contains для byte[]).
    /// Используется вместо PayloadHex.Contains, который обрезан до 64 байт.
    /// </summary>
    private static bool ContainsBytes(byte[] data, byte[] pattern)
    {
        int limit = Math.Min(data.Length - pattern.Length + 1, 256); // первые 256 байт
        for (int i = 0; i < limit; i++)
        {
            bool found = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j]) { found = false; break; }
            }
            if (found) return true;
        }
        return false;
    }

    private class PortScanState
    {
        private readonly List<(int Port, DateTime Time)> _attempts = new();
        public long TotalAttempts { get; private set; }
        public void AddAttempt(int port, DateTime time) { _attempts.Add((port, time)); TotalAttempts++; }
        public int UniquePortsInWindow(int s) { var c = DateTime.UtcNow.AddSeconds(-s); return _attempts.Where(a => a.Time > c).Select(a => a.Port).Distinct().Count(); }
        public List<int> GetPortsInWindow(int s) { var c = DateTime.UtcNow.AddSeconds(-s); return _attempts.Where(a => a.Time > c).Select(a => a.Port).Distinct().OrderBy(p => p).ToList(); }
        public void PurgeOld(int s) { var c = DateTime.UtcNow.AddSeconds(-s * 3); _attempts.RemoveAll(a => a.Time < c); }
        public void Reset() { _attempts.Clear(); }
    }

    private class BruteForceState
    {
        private readonly List<DateTime> _attempts = new();
        public long TotalAttempts { get; private set; }
        public void AddAttempt(DateTime time) { _attempts.Add(time); TotalAttempts++; }
        public int AttemptsInWindow(int s) { var c = DateTime.UtcNow.AddSeconds(-s); return _attempts.Count(a => a > c); }
        public void PurgeOld(int s) { var c = DateTime.UtcNow.AddSeconds(-s * 3); _attempts.RemoveAll(a => a < c); }
        public void Reset() { _attempts.Clear(); }
    }

    private class SynFloodState
    {
        private readonly List<DateTime> _attempts = new();
        public long TotalAttempts { get; private set; }
        public void AddAttempt(DateTime time) { _attempts.Add(time); TotalAttempts++; }
        public int AttemptsInWindow(int s) { var c = DateTime.UtcNow.AddSeconds(-s); return _attempts.Count(a => a > c); }
        public void PurgeOld(int s) { var c = DateTime.UtcNow.AddSeconds(-s * 3); _attempts.RemoveAll(a => a < c); }
        public void Reset() { _attempts.Clear(); }
    }
}