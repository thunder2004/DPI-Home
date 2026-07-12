namespace DPI_Home.Services;

/// <summary>
/// Базовое состояние скользящего окна. LastActivityUtc нужен уборщику:
/// раньше словари состояний росли бесконечно и никогда не чистились.
/// </summary>
public abstract class WindowState
{
    public DateTime LastActivityUtc { get; protected set; } = DateTime.UtcNow;
    public bool IsStale(TimeSpan ttl) => DateTime.UtcNow - LastActivityUtc > ttl;
    public DateTime LastAlertUtc { get; set; } = DateTime.MinValue;
}

/// <summary>Порт-скан: уникальные целевые порты от одного источника к одной жертве.</summary>
public sealed class PortScanState : WindowState
{
    private readonly List<(int Port, DateTime Time)> _probes = new();
    public long TotalProbes { get; private set; }

    public void AddProbe(int port, DateTime utc)
    {
        _probes.Add((port, utc));
        TotalProbes++;
        LastActivityUtc = DateTime.UtcNow;
        if (_probes.Count > 20_000) _probes.RemoveRange(0, 10_000);   // защита от разрастания
    }

    public void Purge(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        _probes.RemoveAll(p => p.Time < cutoff);
    }

    public int UniquePorts(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        return _probes.Where(p => p.Time > cutoff).Select(p => p.Port).Distinct().Count();
    }

    public HashSet<int> Ports(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        return _probes.Where(p => p.Time > cutoff).Select(p => p.Port).ToHashSet();
    }

    public void Reset() => _probes.Clear();
}

/// <summary>Brute-force: попытки новых соединений (SYN) на один сервисный порт.</summary>
public sealed class BruteForceState : WindowState
{
    private readonly List<DateTime> _attempts = new();
    public long TotalAttempts { get; private set; }

    public void AddAttempt(DateTime utc)
    {
        _attempts.Add(utc);
        TotalAttempts++;
        LastActivityUtc = DateTime.UtcNow;
        if (_attempts.Count > 20_000) _attempts.RemoveRange(0, 10_000);
    }

    public void Purge(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        _attempts.RemoveAll(t => t < cutoff);
    }

    public int InWindow(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        return _attempts.Count(t => t > cutoff);
    }

    public void Reset() => _attempts.Clear();
}

/// <summary>
/// SYN flood: ключ — ЖЕРТВА (DstIp:DstPort), а не источник.
/// Реальный флуд идёт со спуфнутых адресов, поэтому счётчик по SrcIp никогда не срабатывал,
/// зато плодил по записи словаря на каждый поддельный IP.
/// </summary>
public sealed class SynFloodState : WindowState
{
    private readonly List<(DateTime Time, string Src)> _syns = new();
    public long TotalSyns { get; private set; }

    private const int HardCap = 50_000;   // для алерта хватит с запасом

    public void AddSyn(string srcIp, DateTime utc)
    {
        TotalSyns++;
        LastActivityUtc = DateTime.UtcNow;
        if (_syns.Count < HardCap) _syns.Add((utc, srcIp));
    }

    public void Purge(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        _syns.RemoveAll(s => s.Time < cutoff);
    }

    public int InWindow(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        return _syns.Count(s => s.Time > cutoff);
    }

    /// <summary>Число уникальных источников — отличает распределённый/спуфнутый флуд от одиночного скана.</summary>
    public int UniqueSources(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        return _syns.Where(s => s.Time > cutoff).Select(s => s.Src).Distinct().Count();
    }

    public string TopSource(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        return _syns.Where(s => s.Time > cutoff)
                    .GroupBy(s => s.Src)
                    .OrderByDescending(g => g.Count())
                    .Select(g => g.Key)
                    .FirstOrDefault() ?? string.Empty;
    }

    public void Reset() => _syns.Clear();
}

/// <summary>ICMP: частота эхо-пакетов от источника (ping flood / туннель).</summary>
public sealed class IcmpRateState : WindowState
{
    private readonly List<DateTime> _hits = new();
    public long TotalHits { get; private set; }

    public void Add(DateTime utc)
    {
        _hits.Add(utc);
        TotalHits++;
        LastActivityUtc = DateTime.UtcNow;
        if (_hits.Count > 20_000) _hits.RemoveRange(0, 10_000);
    }

    public void Purge(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        _hits.RemoveAll(t => t < cutoff);
    }

    public int InWindow(int windowSeconds)
    {
        var cutoff = DateTime.UtcNow.AddSeconds(-windowSeconds);
        return _hits.Count(t => t > cutoff);
    }

    public void Reset() => _hits.Clear();
}
