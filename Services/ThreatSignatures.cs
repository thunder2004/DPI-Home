using System.Text;
using DPI_Home.Models;

namespace DPI_Home.Services;

public record ThreatSignature
{
    public string Name { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public ThreatLevel Level { get; init; } = ThreatLevel.Medium;
    public string Description { get; init; } = string.Empty;
    public Func<RawPacket, bool> Match { get; init; } = _ => false;
}

public static class ThreatSignatures
{
    /// <summary>Unified scale: previously signatures used (int)Level*25, behavioral used hardcoded 75/90/95.</summary>
    public static double ScoreFor(ThreatLevel level) => level switch
    {
        ThreatLevel.Info => 10,
        ThreatLevel.Low => 30,
        ThreatLevel.Medium => 50,
        ThreatLevel.High => 75,
        ThreatLevel.Critical => 95,
        _ => 0
    };

    public static List<ThreatSignature> LoadAll() => new()
    {
        // ─────────────── TCP stealth scans ───────────────
        // All checks require TcpFlagsParsed: for non-first fragments and truncated packets,
        // "flags" are random bytes and previously produced phantom High alerts.

        new() { Name = "NULL Scan", Category = "Recon", Level = ThreatLevel.High,
            Description = "TCP packet with no flags — stack scanning",
            Match = p => p.IsTcp && p.TcpFlagsParsed && p.IsFirstFragment
                      && (p.TcpFlags & 0x3F) == 0x00 && p.DstPort > 0 },

        new() { Name = "FIN Scan", Category = "Recon", Level = ThreatLevel.Medium,
            Description = "TCP packet with only FIN flag — stealth scanning",
            Match = p => p.IsTcp && p.TcpFlagsParsed && p.IsFirstFragment
                      && (p.TcpFlags & 0x3F) == 0x01 },

        // XMAS: FIN+PSH+URG without SYN/ACK/RST (mask 0x14 = ACK|RST).
        // Previously the mask didn't exclude RST, so RST+FIN+PSH+URG also matched.
        new() { Name = "XMAS Scan", Category = "Recon", Level = ThreatLevel.High,
            Description = "TCP packet with FIN+PSH+URG — XMAS scanning",
            Match = p => p.IsTcp && p.TcpFlagsParsed && p.IsFirstFragment
                      && (p.TcpFlags & 0x29) == 0x29 && (p.TcpFlags & 0x14) == 0 },

        // ─────────────── Exploit ───────────────

        // MS17-010: SMBv1 on 445 with Trans2 (0x32) or Trans2 Secondary (0x33) command.
        // Previously ANY \xFFSMB matched, giving Critical on every Shodan scan.
        new() { Name = "EternalBlue (MS17-010)", Category = "Exploit", Level = ThreatLevel.Critical,
            Description = "SMBv1 Trans2 on port 445 — MS17-010 exploit pattern",
            Match = p => p.IsTcp && p.DstPort == 445 && p.IsFirstFragment
                      && MatchEternalBlue(p.L4Payload) },

        // Plain SMBv1 outbound — not an exploit, but high risk (legacy protocol).
        new() { Name = "SMBv1 Exposure", Category = "Exploit", Level = ThreatLevel.High,
            Description = "SMBv1 traffic on port 445 (scanner / legacy protocol)",
            Match = p => p.IsTcp && p.DstPort == 445 && p.IsFirstFragment
                      && ContainsSmbMagic(p.L4Payload) && !MatchEternalBlue(p.L4Payload) },

        // ─────────────── C2 / Tunnel ───────────────

        // DNS Tunneling: previously checked PacketLength (entire UDP datagram with headers),
        // now checks L4PayloadLength (DNS data only). Threshold 512 bytes = EDNS0 limit.
        // UDP only: TCP DNS is normal for zone transfer and DNSSEC.
        new() { Name = "DNS Tunneling", Category = "C2/Tunnel", Level = ThreatLevel.High,
            Description = "UDP DNS payload > 512 bytes — possible DNS tunnel",
            Match = p => p.IsUdp && p.DstPort == 53 && p.L4PayloadLength > 512 },

        // ICMP Tunneling: check L4PayloadLength, not entire PacketLength.
        new() { Name = "ICMP Tunneling", Category = "C2/Tunnel", Level = ThreatLevel.High,
            Description = "ICMP payload > 1000 bytes — possible ICMP tunnel",
            Match = p => p.IsIcmp && p.L4PayloadLength > 1000 },
    };

    // ── SMB helpers ──

    /// <summary>Searches for \xFFSMB magic at the start of L4-payload (up to 8 bytes from start).</summary>
    private static bool ContainsSmbMagic(ReadOnlySpan<byte> payload)
    {
        ReadOnlySpan<byte> magic = stackalloc byte[] { 0xFF, 0x53, 0x4D, 0x42 };
        int limit = Math.Min(payload.Length - magic.Length + 1, 8);
        for (int i = 0; i < limit; i++)
            if (payload.Slice(i, magic.Length).SequenceEqual(magic)) return true;
        return false;
    }

    /// <summary>
    /// MS17-010: SMBv1 with Trans2 (0x32) or Trans2 Secondary (0x33).
    /// The command is at the 4th byte after magic.
    /// </summary>
    private static bool MatchEternalBlue(ReadOnlySpan<byte> payload)
    {
        ReadOnlySpan<byte> magic = stackalloc byte[] { 0xFF, 0x53, 0x4D, 0x42 };
        int limit = Math.Min(payload.Length - magic.Length + 1, 8);
        for (int i = 0; i < limit; i++)
        {
            if (!payload.Slice(i, magic.Length).SequenceEqual(magic)) continue;
            int cmdIdx = i + 4;
            if (cmdIdx >= payload.Length) return false;
            byte cmd = payload[cmdIdx];
            return cmd is 0x32 or 0x33;
        }
        return false;
    }
}