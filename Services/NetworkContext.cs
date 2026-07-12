using System.Net;
using System.Net.Sockets;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Описывает топологию: какие подсети «наши» и какие IP — наши WAN-адреса.
/// На основе этого пакетам присваивается направление (Inbound/Outbound/Internal).
/// Заменяет хрупкую эвристику IsPrivateIp: теперь фильтрация осознанная и настраиваемая.
/// </summary>
public class NetworkContext
{
    private readonly List<(uint Network, uint Mask)> _localSubnets = new();
    private readonly HashSet<uint> _wanIps = new();

    /// <summary>
    /// Точка съёма трафика. Влияет на то, какие направления имеет смысл анализировать.
    /// </summary>
    public CaptureVantage Vantage { get; set; } = CaptureVantage.Wan;

    public enum CaptureVantage
    {
        Wan,  // сниффер видит WAN-интерфейс: интересен Inbound
        Lan,  // сниффер видит LAN: интересен Internal + Outbound (заражённые хосты)
        Both
    }

    /// <summary>
    /// Создаёт контекст с дефолтами RFC1918. WAN-IP нужно добавить явно через AddWanIp,
    /// иначе исходящий трафик с публичного WAN-адреса будет считаться Inbound.
    /// </summary>
    public static NetworkContext CreateDefault()
    {
        var ctx = new NetworkContext();
        ctx.AddLocalSubnet("10.0.0.0/8");
        ctx.AddLocalSubnet("172.16.0.0/12");
        ctx.AddLocalSubnet("192.168.0.0/16");
        ctx.AddLocalSubnet("100.64.0.0/10");   // CGNAT
        ctx.AddLocalSubnet("169.254.0.0/16");  // link-local
        ctx.AddLocalSubnet("127.0.0.0/8");     // loopback
        return ctx;
    }

    public void AddLocalSubnet(string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2) return;
        if (!TryIpToUint(parts[0], out uint net)) return;
        if (!int.TryParse(parts[1], out int prefix) || prefix < 0 || prefix > 32) return;
        uint mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
        _localSubnets.Add((net & mask, mask));
    }

    public void AddWanIp(string ip)
    {
        if (TryIpToUint(ip, out uint v)) _wanIps.Add(v);
    }

    public bool IsLocal(string ip) =>
        TryIpToUint(ip, out uint v) && IsLocal(v);

    private bool IsLocal(uint ip)
    {
        foreach (var (net, mask) in _localSubnets)
            if ((ip & mask) == net) return true;
        return false;
    }

    private bool IsOurs(uint ip) => _wanIps.Contains(ip) || IsLocal(ip);

    /// <summary>
    /// Классифицирует пакет по направлению. Только IPv4 (v6 отсекается парсером).
    /// </summary>
    public TrafficDirection Classify(string srcIp, string dstIp)
    {
        bool srcOk = TryIpToUint(srcIp, out uint s);
        bool dstOk = TryIpToUint(dstIp, out uint d);
        if (!srcOk || !dstOk) return TrafficDirection.Unknown;

        bool srcOurs = IsOurs(s);
        bool dstOurs = IsOurs(d);

        if (srcOurs && dstOurs) return TrafficDirection.Internal;
        if (!srcOurs && dstOurs) return TrafficDirection.Inbound;
        if (srcOurs && !dstOurs) return TrafficDirection.Outbound;
        return TrafficDirection.Unknown; // ни src, ни dst не наши — транзит/мусор
    }

    private static bool TryIpToUint(string ip, out uint value)
    {
        value = 0;
        if (!IPAddress.TryParse(ip, out var addr)) return false;
        if (addr.AddressFamily != AddressFamily.InterNetwork) return false; // только IPv4
        var b = addr.GetAddressBytes();
        value = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        return true;
    }
}
