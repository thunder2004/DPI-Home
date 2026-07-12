using System.Net;
using System.Net.Sockets;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Describes topology: which subnets are "ours" and which IPs are our WAN addresses.
/// Based on this, packets are assigned a direction (Inbound/Outbound/Internal).
/// Replaces fragile IsPrivateIp heuristic: classification is now explicit and configurable.
/// </summary>
public class NetworkContext
{
    private readonly List<(uint Network, uint Mask)> _localSubnets = new();
    private readonly HashSet<uint> _wanIps = new();

    /// <summary>
    /// Traffic capture vantage point. Affects which directions are meaningful to analyze.
    /// </summary>
    public CaptureVantage Vantage { get; set; } = CaptureVantage.Wan;

    public enum CaptureVantage
    {
        Wan,  // sniffer sees WAN interface: Inbound is interesting
        Lan,  // sniffer sees LAN: Internal + Outbound interesting (infected hosts)
        Both
    }

    /// <summary>
    /// Creates a context with RFC1918 defaults. WAN-IP must be added explicitly via AddWanIp,
    /// otherwise outgoing traffic from the public WAN address will be classified as Inbound.
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

    /// <summary>
    /// Well-known public services that must never be auto-blocked
    /// (DNS resolvers, CDN, NTP, major clouds). Alerts for them are still
    /// shown — only automatic blocking is suppressed.
    /// </summary>
    public bool IsWellKnown(string ip) =>
        TryIpToUint(ip, out uint v) && IsWellKnown(v);

    private static readonly HashSet<uint> WellKnownIps = new()
    {
        // Google Public DNS
        IpToUint("8.8.8.8"), IpToUint("8.8.4.4"),
        // Cloudflare DNS
        IpToUint("1.1.1.1"), IpToUint("1.0.0.1"),
        // Quad9
        IpToUint("9.9.9.9"), IpToUint("149.112.112.112"),
        // OpenDNS
        IpToUint("208.67.222.222"), IpToUint("208.67.220.220"),
        // Cloudflare CDN (often triggers ICMP Tunneling)
        IpToUint("1.1.1.2"), IpToUint("1.0.0.2"),
        // NTP pool (often triggers on large packets)
        IpToUint("129.6.15.28"), IpToUint("129.6.15.29"),  // time.nist.gov
        // Apple DNS
        IpToUint("17.253.144.10"), IpToUint("17.253.144.11"),
        IpToUint("17.253.144.254"),
    };

    private static uint IpToUint(string ip)
    {
        TryIpToUint(ip, out uint v);
        return v;
    }

    private bool IsWellKnown(uint ip) => WellKnownIps.Contains(ip);

    private bool IsLocal(uint ip)
    {
        foreach (var (net, mask) in _localSubnets)
            if ((ip & mask) == net) return true;
        return false;
    }

    private bool IsOurs(uint ip) => _wanIps.Contains(ip) || IsLocal(ip);

    /// <summary>
    /// Classifies a packet by direction. IPv4 only (v6 is filtered by the parser).
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
        return TrafficDirection.Unknown; // neither src nor dst are ours — transit/garbage
    }

    private static bool TryIpToUint(string ip, out uint value)
    {
        value = 0;
        if (!IPAddress.TryParse(ip, out var addr)) return false;
        if (addr.AddressFamily != AddressFamily.InterNetwork) return false; // IPv4 only
        var b = addr.GetAddressBytes();
        value = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        return true;
    }
}