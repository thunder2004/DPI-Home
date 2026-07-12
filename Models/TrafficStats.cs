namespace DPI_Home.Models;

/// <summary>
/// Real-time traffic statistics
/// </summary>
public class TrafficStats
{
    public long TotalPackets { get; set; }
    public long TotalBytes { get; set; }
    public double PacketsPerSecond { get; set; }
    public double BytesPerSecond { get; set; }
    public int ActiveConnections { get; set; }
    public int AlertsToday { get; set; }
    public int AlertsCritical { get; set; }
    public int AlertsHigh { get; set; }
    public int AlertsMedium { get; set; }
    public string TopSrcIp { get; set; } = string.Empty;
    public string TopDstPort { get; set; } = string.Empty;
    public string TopProtocol { get; set; } = string.Empty;
}