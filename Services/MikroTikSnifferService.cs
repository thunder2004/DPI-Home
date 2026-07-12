using System.Net;
using System.Net.Sockets;
using System.IO;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Сервис захвата трафика с MikroTik через Packet Sniffer (TZSP over UDP).
/// MikroTik шлёт UDP-датаграммы с TZSP-заголовком переменной длины,
/// внутри которого инкапсулирован Ethernet-кадр.
/// </summary>
public class MikroTikSnifferService : IDisposable
{
    private readonly int _listenPort;
    private UdpClient? _udpClient;
    private CancellationTokenSource? _cts;
    private Task? _readTask;
    private bool _firstPacketDumped;

    // TZSP константы
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
            OnError?.Invoke($"✅ UDP сервер запущен на порту {_listenPort}, ожидаю пакеты от MikroTik...");
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
                $"Первый пакет ({data.Length} байт):\n{hex}");
        }
        catch { }
        OnError?.Invoke($"🔗 Первый пакет ({data.Length} байт) — дамп сохранён в packet_dump.txt");
    }

    /// <summary>
    /// Разбирает TZSP-заголовок переменной длины. Возвращает смещение начала
    /// инкапсулированного Ethernet-кадра, либо -1 если это не Ethernet-over-TZSP.
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
            if (tag == TzspTagEnd) return i + 1;      // конец тегов → дальше Ethernet
            if (tag == TzspTagPadding) { i++; continue; }
            if (i + 1 >= len) return -1;
            int tagLen = d[i + 1];
            i += 2 + tagLen;                          // tag(1) + len(1) + data(tagLen)
        }
        return -1; // TAG_END не найден
    }

    private static RawPacket? ParsePacket(byte[] data, int length)
    {
        try
        {
            int ethOff = ParseTzspHeader(data, length);
            if (ethOff < 0) return null;

            // Ethernet-заголовок: 14 байт минимум
            if (ethOff + 14 > length) return null;

            var packet = new RawPacket
            {
                Timestamp = DateTime.UtcNow,
                PacketLength = length,
                PayloadRaw = data,          // держим весь буфер; срезы через L4Payload
                PayloadHex = Convert.ToHexString(data, 0, Math.Min(length, 64))
            };

            packet.DstMac = BitConverter.ToString(data, ethOff + 0, 6).Replace('-', ':');
            packet.SrcMac = BitConverter.ToString(data, ethOff + 6, 6).Replace('-', ':');

            int etherType = (data[ethOff + 12] << 8) | data[ethOff + 13];
            int ipOffset = ethOff + 14;

            // 802.1Q / QinQ VLAN — по 4 байта на тег
            while (etherType == EthTypeVlan || etherType == EthTypeQinQ)
            {
                if (ipOffset + 4 > length) return null;
                etherType = (data[ipOffset + 2] << 8) | data[ipOffset + 3];
                ipOffset += 4;
            }

            if (etherType == EthTypeIpv6)
            {
                // IPv6 пока не поддержан детекторами — помечаем и не парсим L4.
                packet.Protocol = "IPv6";
                return packet;
            }
            if (etherType != EthTypeIpv4) return null; // ARP, PPPoE и пр. — не наш случай

            if (ipOffset + 20 > length) return packet; // недостаточно на IP-заголовок

            int versionIhl = data[ipOffset];
            if ((versionIhl >> 4) != 4) return null;   // не IPv4
            int ihl = (versionIhl & 0x0F) * 4;
            if (ihl < 20 || ipOffset + ihl > length) return packet; // битый IHL

            packet.IpTotalLength = (data[ipOffset + 2] << 8) | data[ipOffset + 3];

            // Флаги фрагментации / offset
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

            // Для не-первых фрагментов L4-заголовка нет — порты/флаги НЕ читаем.
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
                if (transportOffset + 20 > length) return packet; // минимум TCP-заголовка
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
                packet.L4PayloadOffset = transportOffset; // ICMP-заголовок + данные
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
