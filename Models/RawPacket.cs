namespace DPI_Home.Models;

/// <summary>
/// Packet direction relative to the protected network.
/// </summary>
public enum TrafficDirection
{
    Unknown,
    Inbound,   // from outside to us (src external, dst ours)
    Outbound,  // from us to outside
    Internal   // within our subnets (potential lateral movement)
}

/// <summary>
/// Raw packet received from MikroTik Packet Sniffer (TZSP/Ethernet).
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

    /// <summary>Length of the entire captured datagram (TZSP+Eth+IP+...). NOT the L4-payload length.</summary>
    public int PacketLength { get; set; }

    /// <summary>IP packet length from the Total Length field in the IP header (without Eth/TZSP overhead).</summary>
    public int IpTotalLength { get; set; }

    public string PayloadHex { get; set; } = string.Empty;

    /// <summary>The entire captured datagram.</summary>
    public byte[] PayloadRaw { get; set; } = Array.Empty<byte>();

    /// <summary>Offset of the L4-payload start (after TCP/UDP header) within PayloadRaw. -1 if unavailable.</summary>
    public int L4PayloadOffset { get; set; } = -1;

    /// <summary>L4-payload length in bytes (0 if unavailable / no data).</summary>
    public int L4PayloadLength { get; set; }

    public string InterfaceName { get; set; } = string.Empty;
    public byte TcpFlags { get; set; }  // FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32
    public bool TcpFlagsParsed { get; set; }  // true = flags actually parsed (packet not truncated/fragmented)

    /// <summary>true if this is NOT the first fragment (no L4 header).</summary>
    public bool IsNonFirstFragment { get; set; }

    /// <summary>First (or only) fragment — only this one has a valid L4 header.</summary>
    public bool IsFirstFragment => !IsNonFirstFragment;

    public bool IsTcp => Protocol == "TCP";
    public bool IsUdp => Protocol == "UDP";
    public bool IsIcmp => Protocol == "ICMP";

    /// <summary>Direction relative to our subnets (populated by NetworkContext).</summary>
    public TrafficDirection Direction { get; set; } = TrafficDirection.Unknown;

    /// <summary>Convenient access to the L4-payload slice (may be empty).</summary>
    public ReadOnlySpan<byte> L4Payload =>
        L4PayloadOffset >= 0 && L4PayloadOffset + L4PayloadLength <= PayloadRaw.Length
            ? PayloadRaw.AsSpan(L4PayloadOffset, L4PayloadLength)
            : ReadOnlySpan<byte>.Empty;
}