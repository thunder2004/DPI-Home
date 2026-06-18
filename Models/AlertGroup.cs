namespace DPI_Home.Models;

/// <summary>
/// Агрегированный алерт — все события от одного IP
/// </summary>
public class AlertGroup
{
    public string GroupKey { get; set; } = string.Empty;  // srcIp
    public string SrcIp { get; set; } = string.Empty;
    public ThreatLevel MaxLevel { get; set; } = ThreatLevel.Info;
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public long TotalCount { get; set; }
    public Dictionary<string, ThreatInfo> Categories { get; set; } = new();

    public string LevelIcon => MaxLevel switch
    {
        ThreatLevel.Info => "ℹ️",
        ThreatLevel.Low => "⚠️",
        ThreatLevel.Medium => "⚡",
        ThreatLevel.High => "🔴",
        ThreatLevel.Critical => "💀",
        _ => "❓"
    };

    public string LevelColor => MaxLevel switch
    {
        ThreatLevel.Info => "#4FC3F7",
        ThreatLevel.Low => "#FFB74D",
        ThreatLevel.Medium => "#FF9800",
        ThreatLevel.High => "#F44336",
        ThreatLevel.Critical => "#B71C1C",
        _ => "#9E9E9E"
    };

    public string TimeRange
    {
        get
        {
            if (FirstSeen.Date == LastSeen.Date)
                return $"{FirstSeen:HH:mm:ss} — {LastSeen:HH:mm:ss}";
            return $"{FirstSeen:dd HH:mm} — {LastSeen:HH:mm:ss}";
        }
    }

    public string Summary
    {
        get
        {
            var parts = Categories
                .OrderByDescending(c => c.Value.Count)
                .Select(c => $"{c.Value.Icon}{c.Key} x{c.Value.Count}")
                .Take(3);
            var joined = string.Join(" | ", parts);
            var total = Categories.Values.Sum(c => c.Count);
            if (total > 0)
                joined = $"📦 {total:N0} событий\n" + joined;
            return joined;
        }
    }

    public string AttackTypes
    {
        get
        {
            var parts = Categories
                .OrderByDescending(c => c.Value.Count)
                .Select(c => $"{c.Key} x{c.Value.Count}");
            return string.Join(", ", parts);
        }
    }

    public string CountLabel => TotalCount switch
    {
        1 => "1 раз",
        <= 10 => $"{TotalCount} раз",
        <= 100 => $"{TotalCount} раз",
        _ => $"{TotalCount:N0} раз"
    };
}

public class ThreatInfo
{
    public string Icon { get; set; } = "❓";
    public int Count { get; set; }
}