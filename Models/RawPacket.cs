namespace DPI_Home.Models;

/// <summary>
/// Сырой пакет, полученный от MikroTik Packet Sniffer
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
    public int PacketLength { get; set; }
    public string PayloadHex { get; set; } = string.Empty;
    public byte[] PayloadRaw { get; set; } = Array.Empty<byte>();
    public string InterfaceName { get; set; } = string.Empty;
}
