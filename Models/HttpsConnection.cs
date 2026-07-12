namespace DPI_Home.Models;

/// <summary>
/// Состояние HTTPS/TCP-соединения
/// </summary>
public enum ConnectionState
{
    SynSent,      // SYN отправлен
    Established,  // SYN-ACK получен (рукопожатие завершено)
    Closed,       // FIN/RST
    HalfOpen      // SYN без ответа (подозрительно)
}

/// <summary>
/// Модель HTTPS-соединения для отображения в отдельном окне
/// </summary>
public class HttpsConnection
{
    public DateTime Timestamp { get; set; }
    public string SrcIp { get; set; } = string.Empty;
    public string DstIp { get; set; } = string.Empty;
    public int SrcPort { get; set; }
    public int DstPort { get; set; }

    /// <summary>IP HTTPS-сервера (независимо от того, какой из пакетов пришёл первым). Сохраняется,
    /// чтобы при очистке можно было точно откатиться к нужной группе без перевычисления.</summary>
    public string ServerIp { get; set; } = string.Empty;

    /// <summary>IP внешнего клиента, подключающегося к нам (панель группируется по нему —
    /// т.к. после фильтра "только входящие" ServerIp всегда равен нашему собственному WAN-IP).</summary>
    public string ClientIp { get; set; } = string.Empty;

    public ConnectionState State { get; set; } = ConnectionState.SynSent;
    public long PacketCount { get; set; }
    public long BytesTransferred { get; set; }
    public string Country { get; set; } = string.Empty; // можно будет добавить GeoIP

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
        ConnectionState.Established => "Установлено",
        ConnectionState.Closed => "Закрыто",
        ConnectionState.HalfOpen => "Half-open",
        _ => "?"
    };
}
