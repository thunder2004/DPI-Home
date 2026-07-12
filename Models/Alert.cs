namespace DPI_Home.Models;

/// <summary>
/// Threat level
/// </summary>
public enum ThreatLevel
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Alert — result of packet analysis
/// </summary>
public class Alert
{
    public DateTime Timestamp { get; set; }
    public ThreatLevel Level { get; set; }
    public string Category { get; set; } = string.Empty;  // PortScan, BruteForce, Malware, etc.
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string SrcIp { get; set; } = string.Empty;
    public string DstIp { get; set; } = string.Empty;
    public int SrcPort { get; set; }
    public int DstPort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public long PacketCount { get; set; }
    public double Score { get; set; }
    public string ShortName { get; set; } = string.Empty;
    public HashSet<int> ScannedPorts { get; set; } = new();

    /// <summary>
    /// true if SrcIp is unreliable (likely spoofed — e.g. SYN Flood with many
    /// unique sources). Such IPs must not be auto-blocked: the address may
    /// belong to an innocent bystander, not the attacker.
    /// </summary>
    public bool Spoofed { get; set; }

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
}