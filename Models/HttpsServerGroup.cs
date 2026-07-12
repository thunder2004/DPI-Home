namespace DPI_Home.Models;

/// <summary>
/// Aggregated group of HTTPS connections to one server
/// </summary>
public class HttpsServerGroup
{
    public string DstIp { get; set; } = string.Empty;
    public int TotalConnections { get; set; }
    public int EstablishedCount { get; set; }
    public int SynSentCount { get; set; }
    public int ClosedCount { get; set; }
    public long TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public DateTime LastSeen { get; set; }
    public DateTime FirstSeen { get; set; }

    public string StateIcon => EstablishedCount > 0 ? "🔒" : SynSentCount > 0 ? "🔄" : "✅";
    public string StateColor => EstablishedCount > 0 ? "#4CAF50" : SynSentCount > 0 ? "#FFB74D" : "#78909C";

    public string ConnectionsLabel
    {
        get
        {
            var parts = new List<string>();
            if (EstablishedCount > 0) parts.Add($"🔒{EstablishedCount}");
            if (SynSentCount > 0) parts.Add($"🔄{SynSentCount}");
            if (ClosedCount > 0) parts.Add($"✅{ClosedCount}");
            return string.Join(" ", parts);
        }
    }

    public string TimeRange
    {
        get
        {
            if (FirstSeen.Date == LastSeen.Date)
                return $"{FirstSeen:HH:mm:ss} — {LastSeen:HH:mm:ss}";
            return $"{FirstSeen:dd HH:mm} — {LastSeen:HH:mm:ss}";
        }
    }
}