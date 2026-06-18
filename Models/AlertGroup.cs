namespace DPI_Home.Models;

/// <summary>
/// Агрегированный алерт — группа однотипных событий
/// </summary>
public class AlertGroup
{
    public string GroupKey { get; set; } = string.Empty;  // category + srcIp + dstPort
    public string Category { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string SrcIp { get; set; } = string.Empty;
    public string DstIp { get; set; } = string.Empty;
    public int DstPort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public ThreatLevel Level { get; set; } = ThreatLevel.Medium;
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public long TotalCount { get; set; }
    public double MaxScore { get; set; }

    public string LevelIcon => Level switch
    {
        ThreatLevel.Info => "ℹ️",
        ThreatLevel.Low => "⚠️",
        ThreatLevel.Medium => "⚡",
        ThreatLevel.High => "🔴",
        ThreatLevel.Critical => "💀",
        _ => "❓"
    };

    public string LevelColor => Level switch
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

    public string CountLabel => TotalCount switch
    {
        1 => "1 раз",
        <= 10 => $"{TotalCount} раз",
        <= 100 => $"{TotalCount} раз",
        _ => $"{TotalCount:N0} раз"
    };
}
