using System.Collections.Concurrent;
using System.Text;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Сигнатура угрозы для DPI-анализа
/// </summary>
public record ThreatSignature
{
    public string Name { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public ThreatLevel Level { get; init; } = ThreatLevel.Medium;
    public string Description { get; init; } = string.Empty;
    public Func<RawPacket, bool> Match { get; init; } = _ => false;
}

/// <summary>
/// Анализатор трафика — DPI + сигнатурный анализ + поведенческий анализ
/// </summary>
public class TrafficAnalyzer
{
    private readonly List<ThreatSignature> _signatures;
    private readonly ConcurrentDictionary<string, PortScanState> _portScans = new();
    private readonly ConcurrentDictionary<string, BruteForceState> _bruteForce = new();

    private const int PortScanThreshold = 20;    // уникальных портов за 10 сек
    private const int BruteForceThreshold = 10;   // попыток за 10 сек
    private const int WindowSeconds = 10;

    public event Action<Alert>? OnAlert;

    public TrafficAnalyzer()
    {
        _signatures = LoadSignatures();
    }

    public void Analyze(RawPacket packet)
    {
        // 1. Сигнатурный анализ
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

        // 2. Поведенческий анализ — Port Scan
        DetectPortScan(packet);

        // 3. Поведенческий анализ — Brute Force
        DetectBruteForce(packet);
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

        // Brute force характерен для SSH (22), RDP (3389), HTTP auth (80,443)
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

    private void EmitAlert(Alert alert)
    {
        OnAlert?.Invoke(alert);
    }

    private static List<ThreatSignature> LoadSignatures()
    {
        return new List<ThreatSignature>
        {
            // === Сканирование ===
            new()
            {
                Name = "NULL Scan",
                Category = "Recon",
                Level = ThreatLevel.High,
                Description = "TCP-пакет с нулевыми флагами — попытка сканирования",
                Match = p => p.Protocol == "TCP" && p.PayloadRaw.Length > 20 && (p.PayloadRaw[33] & 0x3F) == 0
            },
            new()
            {
                Name = "XMAS Scan",
                Category = "Recon",
                Level = ThreatLevel.High,
                Description = "TCP-пакет с FIN+PSH+URG — XMAS scan",
                Match = p => p.Protocol == "TCP" && p.PayloadRaw.Length > 20 && (p.PayloadRaw[33] & 0x3F) == 0x29
            },
            new()
            {
                Name = "FIN Scan",
                Category = "Recon",
                Level = ThreatLevel.Medium,
                Description = "TCP-пакет только с FIN флагом",
                Match = p => p.Protocol == "TCP" && p.PayloadRaw.Length > 20 && (p.PayloadRaw[33] & 0x3F) == 0x01
            },

            // === Известные угрозы ===
            new()
            {
                Name = "EternalBlue (SMBv1 Exploit)",
                Category = "Exploit",
                Level = ThreatLevel.Critical,
                Description = "Попытка эксплуатации SMBv1 (EternalBlue/MS17-010)",
                Match = p => p.DstPort == 445 && p.PayloadRaw.Length > 100 &&
                             p.PayloadHex.Contains("000000FF534D42", StringComparison.OrdinalIgnoreCase)
            },
            new()
            {
                Name = "SQL Injection Probe",
                Category = "Web Attack",
                Level = ThreatLevel.High,
                Description = "Попытка SQL-инъекции в HTTP-запросе",
                Match = p => (p.DstPort == 80 || p.DstPort == 443) &&
                             Encoding.UTF8.GetString(p.PayloadRaw).Contains("' OR '1'='1", StringComparison.OrdinalIgnoreCase)
            },
            new()
            {
                Name = "XSS Probe",
                Category = "Web Attack",
                Level = ThreatLevel.Medium,
                Description = "Попытка XSS-атаки в HTTP-запросе",
                Match = p => (p.DstPort == 80 || p.DstPort == 443) &&
                             Encoding.UTF8.GetString(p.PayloadRaw).Contains("<script>", StringComparison.OrdinalIgnoreCase)
            },
            new()
            {
                Name = "DNS Tunneling",
                Category = "C2/Tunnel",
                Level = ThreatLevel.High,
                Description = "Подозрительно длинный DNS-запрос (возможный туннель)",
                Match = p => p.DstPort == 53 && p.PayloadRaw.Length > 200
            },
            new()
            {
                Name = "ICMP Tunneling",
                Category = "C2/Tunnel",
                Level = ThreatLevel.High,
                Description = "Крупный ICMP-пакет (возможный туннель данных)",
                Match = p => p.Protocol == "ICMP" && p.PacketLength > 500
            },
            new()
            {
                Name = "RDP Brute Force",
                Category = "Brute Force",
                Level = ThreatLevel.High,
                Description = "Подозрительная активность на RDP-порту",
                Match = p => p.DstPort == 3389 && p.PacketLength < 100
            },
            new()
            {
                Name = "SSH Anomaly",
                Category = "Anomaly",
                Level = ThreatLevel.Medium,
                Description = "Нестандартный SSH-пакет",
                Match = p => p.DstPort == 22 && p.PacketLength > 1500
            },
            new()
            {
                Name = "MikroTik WinBox Exploit",
                Category = "Exploit",
                Level = ThreatLevel.Critical,
                Description = "Попытка эксплуатации WinBox (CVE-2018-14847)",
                Match = p => p.DstPort == 8291 && p.PayloadRaw.Length > 50
            },
        };
    }

    // Вспомогательные классы для поведенческого анализа
    private class PortScanState
    {
        private readonly List<(int Port, DateTime Time)> _attempts = new();
        public long TotalAttempts { get; private set; }

        public void AddAttempt(int port, DateTime time)
        {
            _attempts.Add((port, time));
            TotalAttempts++;
        }

        public int UniquePortsInWindow(int seconds)
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-seconds);
            return _attempts.Where(a => a.Time > cutoff).Select(a => a.Port).Distinct().Count();
        }

        public void PurgeOld(int seconds)
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-seconds * 3);
            _attempts.RemoveAll(a => a.Time < cutoff);
        }

        public void Reset()
        {
            _attempts.Clear();
        }
    }

    private class BruteForceState
    {
        private readonly List<DateTime> _attempts = new();
        public long TotalAttempts { get; private set; }

        public void AddAttempt(DateTime time)
        {
            _attempts.Add(time);
            TotalAttempts++;
        }

        public int AttemptsInWindow(int seconds)
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-seconds);
            return _attempts.Count(a => a > cutoff);
        }

        public void PurgeOld(int seconds)
        {
            var cutoff = DateTime.UtcNow.AddSeconds(-seconds * 3);
            _attempts.RemoveAll(a => a < cutoff);
        }

        public void Reset()
        {
            _attempts.Clear();
        }
    }
}
