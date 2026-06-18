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

    public void Analyze(RawPacket packet)
    {
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
                    Description = sig.Description,
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    SrcPort = packet.SrcPort,
                    DstPort = packet.DstPort,
                    Protocol = packet.Protocol,
                    PacketCount = 1,
                    Score = (int)sig.Level * 25
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
            if (state.UniquePortsInWindow(WindowSeconds) >= PortScanThreshold)
            {
                EmitAlert(new Alert
                {
                    Timestamp = DateTime.Now,
                    Level = ThreatLevel.High,
                    Category = "Port Scan",
                    Title = "Обнаружен порт-скан",
                    Description = $"IP {packet.SrcIp} сканирует порты: {state.UniquePortsInWindow(WindowSeconds)} уникальных портов за {WindowSeconds}с",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    Protocol = packet.Protocol,
                    PacketCount = state.TotalAttempts,
                    Score = 75
                });
                state.Reset();
            }
        }
    }

    private void DetectBruteForce(RawPacket packet)
    {
        if (string.IsNullOrEmpty(packet.SrcIp) || packet.DstPort == 0) return;
        if (packet.DstPort is not (22 or 3389 or 21 or 1433 or 3306 or 5432)) return;
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
                    Description = $"IP {packet.SrcIp} — {state.AttemptsInWindow(WindowSeconds)} попыток за {WindowSeconds}с на порт {packet.DstPort}",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    DstPort = packet.DstPort,
                    Protocol = packet.Protocol,
                    PacketCount = state.TotalAttempts,
                    Score = 90
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
                    Description = $"IP {packet.SrcIp} — {state.AttemptsInWindow(WindowSeconds)} SYN-пакетов за {WindowSeconds}с на порт 443",
                    SrcIp = packet.SrcIp,
                    DstIp = packet.DstIp,
                    DstPort = 443,
                    Protocol = "TCP",
                    PacketCount = state.TotalAttempts,
                    Score = 95
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

        // Cleanup old closed connections
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
        new() { Name = "NULL Scan", Category = "Recon", Level = ThreatLevel.High, Description = "TCP-пакет с нулевыми флагами", Match = p => p.Protocol == "TCP" && p.PayloadRaw.Length > 20 && (p.PayloadRaw[33] & 0x3F) == 0 },
        new() { Name = "XMAS Scan", Category = "Recon", Level = ThreatLevel.High, Description = "TCP-пакет с FIN+PSH+URG", Match = p => p.Protocol == "TCP" && p.PayloadRaw.Length > 20 && (p.PayloadRaw[33] & 0x3F) == 0x29 },
        new() { Name = "FIN Scan", Category = "Recon", Level = ThreatLevel.Medium, Description = "TCP-пакет только с FIN флагом", Match = p => p.Protocol == "TCP" && p.PayloadRaw.Length > 20 && (p.PayloadRaw[33] & 0x3F) == 0x01 },
        new() { Name = "EternalBlue", Category = "Exploit", Level = ThreatLevel.Critical, Description = "EternalBlue/MS17-010", Match = p => p.DstPort == 445 && p.PayloadRaw.Length > 100 && p.PayloadHex.Contains("000000FF534D42", StringComparison.OrdinalIgnoreCase) },
        new() { Name = "SQL Injection", Category = "Web Attack", Level = ThreatLevel.High, Description = "SQL-инъекция в HTTP", Match = p => (p.DstPort == 80 || p.DstPort == 443) && Encoding.UTF8.GetString(p.PayloadRaw).Contains("' OR '1'='1", StringComparison.OrdinalIgnoreCase) },
        new() { Name = "XSS Probe", Category = "Web Attack", Level = ThreatLevel.Medium, Description = "XSS в HTTP", Match = p => (p.DstPort == 80 || p.DstPort == 443) && Encoding.UTF8.GetString(p.PayloadRaw).Contains("<script>", StringComparison.OrdinalIgnoreCase) },
        new() { Name = "DNS Tunneling", Category = "C2/Tunnel", Level = ThreatLevel.High, Description = "Длинный DNS-запрос", Match = p => p.DstPort == 53 && p.PayloadRaw.Length > 200 },
        new() { Name = "ICMP Tunneling", Category = "C2/Tunnel", Level = ThreatLevel.High, Description = "Крупный ICMP", Match = p => p.Protocol == "ICMP" && p.PacketLength > 500 },
        new() { Name = "RDP Anomaly", Category = "Brute Force", Level = ThreatLevel.High, Description = "Подозрительная RDP активность", Match = p => p.DstPort == 3389 && p.PacketLength < 100 },
        new() { Name = "SSH Anomaly", Category = "Anomaly", Level = ThreatLevel.Medium, Description = "Нестандартный SSH", Match = p => p.DstPort == 22 && p.PacketLength > 1500 },
        new() { Name = "WinBox Exploit", Category = "Exploit", Level = ThreatLevel.Critical, Description = "CVE-2018-14847", Match = p => p.DstPort == 8291 && p.PayloadRaw.Length > 50 },
    };

    private class PortScanState
    {
        private readonly List<(int Port, DateTime Time)> _attempts = new();
        public long TotalAttempts { get; private set; }
        public void AddAttempt(int port, DateTime time) { _attempts.Add((port, time)); TotalAttempts++; }
        public int UniquePortsInWindow(int s) { var c = DateTime.UtcNow.AddSeconds(-s); return _attempts.Where(a => a.Time > c).Select(a => a.Port).Distinct().Count(); }
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