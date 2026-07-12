using System.Net;
using System.Net.Sockets;
using System.IO;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Traffic capture service from MikroTik via Packet Sniffer (TZSP over UDP).
/// MikroTik sends UDP datagrams with a variable-length TZSP header,
/// inside which an Ethernet frame is encapsulated.
/// </summary>
public class MikroTikSnifferService : IDisposable
{
    private readonly int _listenPort;
    private UdpClient? _udpClient;
    private CancellationTokenSource? _cts;
    private Task? _readTask;
    private bool _firstPacketDumped;

    // TZSP constants
    private const byte TzspVersion = 0x01;
    private const int TzspEncapEthernet = 0x0001;
    private const byte TzspTagEnd = 0x01;
    private const byte TzspTagPadding = 0x00;

    // EtherType
    private const int EthTypeIpv4 = 0x0800;
    private const int EthTypeIpv6 = 0x86DD;
    private const int EthTypeVlan = 0x8100;
    private const int EthTypeQinQ = 0x88A8;

    public event Action<RawPacket>? OnPacketReceived;
    public event Action<string>? OnError;
    public event Action<bool>? OnConnectionChanged;

    public bool IsConnected { get; private set; }
    public int ListenPort => _listenPort;

    public MikroTikSnifferService(int listenPort = 37008)
    {
        _listenPort = listenPort;
    }

    public async Task StartAsync()
    {
        if (_udpClient != null) return;

        _cts = new CancellationTokenSource();
        _firstPacketDumped = false;

        try
        {
            _udpClient = new UdpClient(_listenPort);
            OnError?.Invoke($"✅ UDP server started on port {_listenPort}, waiting for packets from MikroTik...");
            IsConnected = false;
            OnConnectionChanged?.Invoke(false);

            _readTask = ReadLoopAsync(_cts.Token);
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            OnError?.Invoke($"Failed to start UDP listener: {ex.Message}");
            _udpClient = null;
        }
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _udpClient != null)
        {
            try
            {
                var result = await _udpClient.ReceiveAsync(ct);
                var data = result.Buffer;

                if (!IsConnected)
                {
                    DumpFirstPacket(data);
                    IsConnected = true;
                    OnConnectionChanged?.Invoke(true);
                }

                var packet = ParsePacket(data, data.Length);
                if (packet != null)
                    OnPacketReceived?.Invoke(packet);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex)
            {
                OnError?.Invoke($"UDP read error: {ex.Message}");
                break;
            }
        }
    }

    private void DumpFirstPacket(byte[] data)
    {
        if (_firstPacketDumped) return;
        _firstPacketDumped = true;
        var hex = BitConverter.ToString(data, 0, Math.Min(64, data.Length));
        try
        {
            File.WriteAllText(
                Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "packet_dump.txt"),
                $"First packet ({data.Length} bytes):\n{hex}");
        }
        catch { }
        OnError?.Invoke($"🔗 First packet ({data.Length} bytes) — dump saved to packet_dump.txt");
    }

    /// <summary>
    /// Parses the variable-length TZSP header. Returns the offset of the
    /// encapsulated Ethernet frame, or -1 if this is not Ethernet-over-TZSP.
    /// </summary>
    private static int ParseTzspHeader(byte[] d, int len)
    {
        if (len < 4) return -1;
        if (d[0] != TzspVersion) return -1;
        int encap = (d[2] << 8) | d[3];
        if (encap != TzspEncapEthernet) return -1;

        int i = 4;
        while (i < len)
        {
            byte tag = d[i];
            if (tag == TzspTagEnd) return i + 1;      // end of tags → Ethernet follows
            if (tag == TzspTagPadding) { i++; continue; }
            if (i + 1 >= len) return -1;
            int tagLen = d[i + 1];
            i += 2 + tagLen;                          // tag(1) + len(1) + data(tagLen)
        }
        return -1; // TAG_END not found
    }

    private static RawPacket? ParsePacket(byte[] data, int length)
    {
        try
        {
            int ethOff = ParseTzspHeader(data, length);
            if (ethOff < 0) return null;

            // Ethernet header: 14 bytes minimum
            if (ethOff + 14 > length) return null;

            var packet = new RawPacket
            {
                Timestamp = DateTime.UtcNow,
                PacketLength = length,
                PayloadRaw = data,          // keep entire buffer; slices via L4Payload
                PayloadHex = Convert.ToHexString(data, 0, Math.Min(length, 64))
            };

            packet.DstMac = BitConverter.ToString(data, ethOff + 0, 6).Replace('-', ':');
            packet.SrcMac = BitConverter.ToString(data, ethOff + 6, 6).Replace('-', ':');

            int etherType = (data[ethOff + 12] << 8) | data[ethOff + 13];
            int ipOffset = ethOff + 14;

            // 802.1Q / QinQ VLAN — 4 bytes per tag
            while (etherType == EthTypeVlan || etherType == EthTypeQinQ)
            {
                if (ipOffset + 4 > length) return null;
                etherType = (data[ipOffset + 2] << 8) | data[ipOffset + 3];
                ipOffset += 4;
            }

            if (etherType == EthTypeIpv6)
            {
                // IPv6 not yet supported by detectors — mark and skip L4 parsing.
                packet.Protocol = "IPv6";
                return packet;
            }
            if (etherType != EthTypeIpv4) return null; // ARP, PPPoE etc. — not our case

            if (ipOffset + 20 > length) return packet; // not enough for IP header

            int versionIhl = data[ipOffset];
            if ((versionIhl >> 4) != 4) return null;   // not IPv4
            int ihl = (versionIhl & 0x0F) * 4;
            if (ihl < 20 || ipOffset + ihl > length) return packet; // bad IHL

            packet.IpTotalLength = (data[ipOffset + 2] << 8) | data[ipOffset + 3];

            // Fragmentation flags / offset
            int flagsFrag = (data[ipOffset + 6] << 8) | data[ipOffset + 7];
            int fragOffset = flagsFrag & 0x1FFF;
            packet.IsNonFirstFragment = fragOffset != 0;

            packet.SrcIp = new IPAddress(data[(ipOffset + 12)..(ipOffset + 16)]).ToString();
            packet.DstIp = new IPAddress(data[(ipOffset + 16)..(ipOffset + 20)]).ToString();

            byte protocol = data[ipOffset + 9];
            packet.Protocol = protocol switch
            {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                _ => $"IP-{protocol}"
            };

            // Non-first fragments have no L4 header — don't read ports/flags.
            if (packet.IsNonFirstFragment)
                return packet;

            int transportOffset = ipOffset + ihl;

            if (protocol == 6 || protocol == 17) // TCP / UDP
            {
                if (transportOffset + 4 > length) return packet;
                packet.SrcPort = (data[transportOffset] << 8) | data[transportOffset + 1];
                packet.DstPort = (data[transportOffset + 2] << 8) | data[transportOffset + 3];
            }

            if (protocol == 6) // TCP
            {
                if (transportOffset + 20 > length) return packet; // minimum TCP header
                packet.TcpFlags = data[transportOffset + 13];
                packet.TcpFlagsParsed = true;

                int dataOffsetWords = (data[transportOffset + 12] >> 4) & 0x0F;
                int tcpHeaderLen = dataOffsetWords * 4;
                if (tcpHeaderLen < 20) tcpHeaderLen = 20;
                packet.L4PayloadOffset = transportOffset + tcpHeaderLen;
            }
            else if (protocol == 17) // UDP
            {
                if (transportOffset + 8 > length) return packet;
                packet.L4PayloadOffset = transportOffset + 8;
            }
            else if (protocol == 1) // ICMP
            {
                packet.L4PayloadOffset = transportOffset; // ICMP header + data
            }

            if (packet.L4PayloadOffset >= 0 && packet.L4PayloadOffset <= length)
                packet.L4PayloadLength = length - packet.L4PayloadOffset;

            return packet;
        }
        catch
        {
            return null;
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        _udpClient?.Dispose();
        _udpClient = null;
        _readTask?.Wait(TimeSpan.FromSeconds(2));
        _cts?.Dispose();
        _cts = null;
        IsConnected = false;
        OnConnectionChanged?.Invoke(false);
    }

    public void Dispose() => Stop();
}