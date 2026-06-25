using System.Collections.Concurrent;
using System.Text;
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

    private const int PortScanThreshold = 20;
    private const int BruteForceThreshold = 10;
    private const int SynFloodThreshold = 100;
    private const int WindowSeconds = 10;

    public event Action<Alert>? OnAlert;
    public event Action<HttpsConnection>? OnHttpsConnectionUpdate;
    public event Action<HttpsServerGroup>? OnHttpsServerGroupUpdate;

    public IReadOnlyCollection<HttpsConnection> HttpsConnections =>
        _httpsConnections.Values.ToList().AsReadOnly();

    public TrafficAnalyzer() => _signatures = LoadSignatures();

    /// <summary>
    /// Проверяет, является ли IP локальным (RFC 1918 + link-local).
    /// Пакеты от таких IP в контексте WAN rx — это NAT-reflection или артефакты,
    /// их не следует считать угрозами.
    /// </summary>
    private static bool IsPrivateIp(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return false;
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8
        return ip.StartsWith("10.") ||
               ip.StartsWith("192.168.") ||
               ip.StartsWith("127.") ||
               ip.StartsWith("169.254.") ||
               (ip.StartsWith("172.") && int.TryParse(ip.Substring(4, ip.IndexOf('.', 4) - 4), out int second) && second >= 16 && second <= 31);
    }

    public void Analyze(RawPacket packet)
    {
        // ── Фильтр: игнорируем пакеты от локальных IP ──
        // В WAN rx-потоке локальные SrcIp — это NAT-reflection или артефакты RouterOS,
        // их не следует считать угрозами.
        if (IsPrivateIp(packet.SrcIp))
            return;

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
        // Локальные IP уже отфильтрованы в Analyze()
        var state = _portScans.GetOrAdd(packet.SrcIp, _ => new PortScanState());
        lock (state)
        {
            state.PurgeOld(WindowSeconds);
            state.AddAttempt(packet.DstPort, packet.Timestamp);
            if (state.UniquePortsInWindow(WindowSeconds) >= PortScanThreshold)
            {
                EmitAlert(new Alert
                {
                    Timestamp = DateTime.Now,
                    Level = ThreatLevel.High,
                    Category = "Port Scan",
                    Title = "Обнаружен порт-скан",
                    ShortName = "Port Scan",
                    Description = $"IP {packet.SrcIp} сканирует порты: {state.UniquePortsInWindow(WindowSeconds)} уникальных портов за {WindowSeconds}с",
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
        // Локальные IP уже отфильтрованы в Analyze()
        var key = $"{packet.SrcIp}:{packet.DstPort}";
        var state = _bruteForce.GetOrAdd(key, _ => new BruteForceState());
        lock (state)
        {
            state.PurgeOld(WindowSeconds);
            state.AddAttempt(packet.Timestamp);
            if (state.AttemptsInWindow(WindowSeconds) >= BruteForceThreshold)
            {
                EmitAlert(new Alert
                {
                    Timestamp = DateTime.Now,
                    Level = ThreatLevel.Critical,
                    Category = "Brute Force",
                    Title = $"Brute-force атака на порт {packet.DstPort}",
                    ShortName = $"BruteForce:{packet.DstPort}",
                    Description = $"IP {packet.SrcIp} — {state.AttemptsInWindow(WindowSeconds)} попыток за {WindowSeconds}с на порт {packet.DstPort}",
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
        if (packet.DstPort != 443 || packet.Protocol != "TCP") return;
        bool isSyn = (packet.TcpFlags & 0x02) != 0;
        bool isAck = (packet.TcpFlags & 0x10) != 0;
        if (!isSyn || isAck) return;
        // Локальные IP уже отфильтрованы в Analyze()
        var state = _synFloods.GetOrAdd(packet.SrcIp, _ => new SynFloodState());
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
                    Title = $"SYN Flood атака на порт 443 с {packet.SrcIp}",
                    ShortName = "SYN Flood",
                    Description = $"IP {packet.SrcIp} — {state.AttemptsInWindow(WindowSeconds)} SYN-пакетов за {WindowSeconds}с на порт 443",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    DstPort = 443,
                    Protocol = "TCP",
                    PacketCount = state.TotalAttempts,
                    Score = 95,
                    ScannedPorts = new HashSet<int> { 443 }
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
            foreach (var key in _httpsConnections.Keys)
            {
                if (_httpsConnections.TryGetValue(key, out var c) &&
                    c.State == ConnectionState.Closed &&
                    c.Timestamp < cutoff)
                {
                    cleanedServers.Add(c.SrcIp);
                    cleanedServers.Add(c.DstIp);
                    _httpsConnections.TryRemove(key, out _);
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
        // ─── TCP Scan Signatures (using TcpFlags field, NOT PayloadRaw offsets) ───
        new() { Name = "NULL Scan", Category = "Recon", Level = ThreatLevel.High,
            Description = "TCP NULL Scan — пакет без флагов",
            Match = p => p.Protocol == "TCP" && p.TcpFlags == 0x00 && p.DstPort > 0 },

        new() { Name = "XMAS Scan", Category = "Recon", Level = ThreatLevel.High,
            Description = "TCP XMAS Scan — FIN+PSH+URG флаги",
            Match = p => p.Protocol == "TCP" && (p.TcpFlags & 0x29) == 0x29 && (p.TcpFlags & 0x12) == 0 },

        new() { Name = "FIN Scan", Category = "Recon", Level = ThreatLevel.Medium,
            Description = "TCP FIN Scan — только FIN флаг",
            Match = p => p.Protocol == "TCP" && (p.TcpFlags & 0x3F) == 0x01 },

        // ─── Exploit Signatures ───
        new() { Name = "EternalBlue", Category = "Exploit", Level = ThreatLevel.Critical,
            Description = "EternalBlue/MS17-010 — SMB эксплойт",
            Match = p => p.DstPort == 445 && p.PayloadRaw.Length > 100 && p.PayloadHex.Contains("000000FF534D42", StringComparison.OrdinalIgnoreCase) },

        new() { Name = "WinBox Exploit", Category = "Exploit", Level = ThreatLevel.Critical,
            Description = "CVE-2018-14847 — WinBox exploit",
            Match = p => p.DstPort == 8291 && p.PayloadRaw.Length > 50 && p.PacketLength > 100 },

        // ─── C2/Tunnel Signatures ───
        new() { Name = "DNS Tunneling", Category = "C2/Tunnel", Level = ThreatLevel.High,
            Description = "Подозрительно длинный DNS-запрос (>500 байт)",
            Match = p => p.DstPort == 53 && p.PacketLength > 500 },

        new() { Name = "ICMP Tunneling", Category = "C2/Tunnel", Level = ThreatLevel.High,
            Description = "Аномально большой ICMP-пакет",
            Match = p => p.Protocol == "ICMP" && p.PacketLength > 1000 },
    };

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