namespace DPI_Home.Models;

/// <summary>
/// HTTPS/TCP connection state
/// </summary>
public enum ConnectionState
{
    SynSent,      // SYN sent
    Established,  // SYN-ACK received (handshake complete)
    Closed,       // FIN/RST
    HalfOpen      // SYN without response (suspicious)
}

/// <summary>
/// HTTPS connection model for display
/// </summary>
public class HttpsConnection
{
    public DateTime Timestamp { get; set; }
    public string SrcIp { get; set; } = string.Empty;
    public string DstIp { get; set; } = string.Empty;
    public int SrcPort { get; set; }
    public int DstPort { get; set; }

    /// <summary>HTTPS server IP (regardless of which packet arrived first). Stored
    /// so cleanup can accurately roll back the right group without recomputation.</summary>
    public string ServerIp { get; set; } = string.Empty;

    /// <summary>External client IP connecting to us (panel groups by this —
    /// since after "inbound only" filter ServerIp always equals our own WAN-IP).</summary>
    public string ClientIp { get; set; } = string.Empty;

    public ConnectionState State { get; set; } = ConnectionState.SynSent;
    public long PacketCount { get; set; }
    public long BytesTransferred { get; set; }
    public string Country { get; set; } = string.Empty; // could add GeoIP later

    public string StateIcon => State switch
    {
        ConnectionState.SynSent => "🔄",
        ConnectionState.Established => "🔒",
        ConnectionState.Closed => "✅",
        ConnectionState.HalfOpen => "⚠️",
        _ => "❓"
    };

    public string StateColor => State switch
    {
        ConnectionState.SynSent => "#FFB74D",
        ConnectionState.Established => "#4CAF50",
        ConnectionState.Closed => "#78909C",
        ConnectionState.HalfOpen => "#F44336",
        _ => "#9E9E9E"
    };

    public string StateLabel => State switch
    {
        ConnectionState.SynSent => "SYN",
        ConnectionState.Established => "Established",
        ConnectionState.Closed => "Closed",
        ConnectionState.HalfOpen => "Half-open",
        _ => "?"
    };
}