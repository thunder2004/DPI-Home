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
    /// <summary>Единая шкала: раньше сигнатуры считали (int)Level*25, а поведенческие — хардкод 75/90/95.</summary>
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
        // Все проверки требуют TcpFlagsParsed: у не-первого фрагмента и truncated-пакета
        // "флаги" — это случайные байты, и раньше они давали фантомные High-алерты.

        new() { Name = "NULL Scan", Category = "Recon", Level = ThreatLevel.High,
            Description = "TCP-пакет без единого флага — сканирование стека",
            Match = p => p.IsTcp && p.TcpFlagsParsed && p.IsFirstFragment
                      && (p.TcpFlags & 0x3F) == 0x00 && p.DstPort > 0 },

        new() { Name = "FIN Scan", Category = "Recon", Level = ThreatLevel.Medium,
            Description = "TCP-пакет только с флагом FIN — скрытое сканирование",
            Match = p => p.IsTcp && p.TcpFlagsParsed && p.IsFirstFragment
                      && (p.TcpFlags & 0x3F) == 0x01 },

        // XMAS: FIN+PSH+URG без SYN/ACK/RST (маска 0x14 = ACK|RST).
        // Раньше маска не исключала RST, поэтому RST+FIN+PSH+URG тоже матчился.
        new() { Name = "XMAS Scan", Category = "Recon", Level = ThreatLevel.High,
            Description = "TCP-пакет с FIN+PSH+URG — XMAS-сканирование",
            Match = p => p.IsTcp && p.TcpFlagsParsed && p.IsFirstFragment
                      && (p.TcpFlags & 0x29) == 0x29 && (p.TcpFlags & 0x14) == 0 },

        // ─────────────── Exploit ───────────────

        // MS17-010: SMBv1 на 445 с командой Trans2 (0x32) или Trans2 Secondary (0x33).
        // Раньше матчился ЛЮБОЙ \xFFSMB, что давало Critical на каждый Shodan-скан.
        new() { Name = "EternalBlue (MS17-010)", Category = "Exploit", Level = ThreatLevel.Critical,
            Description = "SMBv1 Trans2 на порт 445 — паттерн эксплойта MS17-010",
            Match = p => p.IsTcp && p.DstPort == 445 && p.IsFirstFragment
                      && MatchEternalBlue(p.L4Payload) },

        // Обычный SMBv1 наружу — не эксплойт, но высокий риск (устаревший протокол).
        new() { Name = "SMBv1 Exposure", Category = "Exploit", Level = ThreatLevel.High,
            Description = "SMBv1-трафик на порт 445 (сканер / устаревший протокол)",
            Match = p => p.IsTcp && p.DstPort == 445 && p.IsFirstFragment
                      && ContainsSmbMagic(p.L4Payload) && !MatchEternalBlue(p.L4Payload) },

        // ─────────────── C2 / Tunnel ───────────────

        // DNS Tunneling: раньше проверялся PacketLength (весь UDP-датаграмм с заголовками),
        // теперь — L4PayloadLength (только DNS-данные). Порог 512 байт = EDNS0 limit.
        // Только UDP: TCP DNS — норма для zone transfer и DNSSEC.
        new() { Name = "DNS Tunneling", Category = "C2/Tunnel", Level = ThreatLevel.High,
            Description = "UDP DNS-payload > 512 байт — возможный DNS-туннель",
            Match = p => p.IsUdp && p.DstPort == 53 && p.L4PayloadLength > 512 },

        // ICMP Tunneling: проверяем L4PayloadLength, а не весь PacketLength.
        new() { Name = "ICMP Tunneling", Category = "C2/Tunnel", Level = ThreatLevel.High,
            Description = "ICMP payload > 1000 байт — возможный ICMP-туннель",
            Match = p => p.IsIcmp && p.L4PayloadLength > 1000 },
    };

    // ── SMB helpers ──

    /// <summary>Ищет \xFFSMB magic в начале L4-payload (до 8 байт от старта).</summary>
    private static bool ContainsSmbMagic(ReadOnlySpan<byte> payload)
    {
        ReadOnlySpan<byte> magic = stackalloc byte[] { 0xFF, 0x53, 0x4D, 0x42 };
        int limit = Math.Min(payload.Length - magic.Length + 1, 8);
        for (int i = 0; i < limit; i++)
            if (payload.Slice(i, magic.Length).SequenceEqual(magic)) return true;
        return false;
    }

    /// <summary>
    /// MS17-010: SMBv1 с Trans2 (0x32) или Trans2 Secondary (0x33).
    /// Команда идёт на 4-м байте после magic.
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