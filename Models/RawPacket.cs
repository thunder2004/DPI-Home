namespace DPI_Home.Models;

/// <summary>
/// Направление пакета относительно защищаемой сети.
/// </summary>
public enum TrafficDirection
{
    Unknown,
    Inbound,   // из внешней сети к нам (src внешний, dst наш)
    Outbound,  // от нас во внешнюю сеть
    Internal   // внутри наших подсетей (потенциальное латеральное движение)
}

/// <summary>
/// Сырой пакет, полученный от MikroTik Packet Sniffer (TZSP/Ethernet).
/// </summary>
public class RawPacket
{
    public DateTime Timestamp { get; set; }
    public string SrcMac { get; set; } = string.Empty;
    public string DstMac { get; set; } = string.Empty;
    public string SrcIp { get; set; } = string.Empty;
    public string DstIp { get; set; } = string.Empty;
    public int SrcPort { get; set; }
    public int DstPort { get; set; }
    public string Protocol { get; set; } = string.Empty; // TCP, UDP, ICMP, etc.

    /// <summary>Длина всей захваченной датаграммы (TZSP+Eth+IP+...). НЕ длина L4-payload.</summary>
    public int PacketLength { get; set; }

    /// <summary>Длина IP-пакета из поля Total Length IP-заголовка (без Eth/TZSP оверхеда).</summary>
    public int IpTotalLength { get; set; }

    public string PayloadHex { get; set; } = string.Empty;

    /// <summary>Вся захваченная датаграмма целиком.</summary>
    public byte[] PayloadRaw { get; set; } = Array.Empty<byte>();

    /// <summary>Смещение начала L4-payload (после TCP/UDP заголовка) внутри PayloadRaw. -1 если недоступно.</summary>
    public int L4PayloadOffset { get; set; } = -1;

    /// <summary>Длина L4-payload в байтах (0 если недоступно / нет данных).</summary>
    public int L4PayloadLength { get; set; }

    public string InterfaceName { get; set; } = string.Empty;
    public byte TcpFlags { get; set; }  // FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32
    public bool TcpFlagsParsed { get; set; }  // true = флаги реально считаны (пакет не truncated/не фрагмент)

    /// <summary>true, если это НЕ первый фрагмент (L4-заголовка нет).</summary>
    public bool IsNonFirstFragment { get; set; }

    /// <summary>Первый (или единственный) фрагмент — только у него есть валидный L4-заголовок.</summary>
    public bool IsFirstFragment => !IsNonFirstFragment;

    public bool IsTcp => Protocol == "TCP";
    public bool IsUdp => Protocol == "UDP";
    public bool IsIcmp => Protocol == "ICMP";

    /// <summary>Направление относительно наших подсетей (заполняется NetworkContext).</summary>
    public TrafficDirection Direction { get; set; } = TrafficDirection.Unknown;

    /// <summary>Удобный доступ к срезу L4-payload (может быть пустым).</summary>
    public ReadOnlySpan<byte> L4Payload =>
        L4PayloadOffset >= 0 && L4PayloadOffset + L4PayloadLength <= PayloadRaw.Length
            ? PayloadRaw.AsSpan(L4PayloadOffset, L4PayloadLength)
            : ReadOnlySpan<byte>.Empty;
}
