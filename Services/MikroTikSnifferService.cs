using System.Net;
using System.Net.Sockets;
using System.IO;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Сервис захвата трафика с MikroTik через Packet Sniffer (UDP streaming)
/// MikroTik просто шлёт UDP-датаграммы на наш IP:port
/// </summary>
public class MikroTikSnifferService : IDisposable
{
    private readonly int _listenPort;
    private UdpClient? _udpClient;
    private CancellationTokenSource? _cts;
    private Task? _readTask;

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
        if (IsConnected) return;

        _cts = new CancellationTokenSource();

        try
        {
            _udpClient = new UdpClient(_listenPort);
            OnError?.Invoke($"✅ UDP сервер запущен на порту {_listenPort}, ожидаю пакеты от MikroTik...");
            OnConnectionChanged?.Invoke(false);

            _readTask = ReadLoopAsync(_cts.Token);
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            OnError?.Invoke($"Failed to start UDP listener: {ex.Message}");
        }
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        var remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

        while (!ct.IsCancellationRequested && _udpClient != null)
        {
            try
            {
                var result = await _udpClient.ReceiveAsync(ct);
                var data = result.Buffer;

                // При первом пакете логируем первые 64 байта для диагностики
                                if (!IsConnected)
                                {
                                    var hex = BitConverter.ToString(data, 0, Math.Min(64, data.Length));
                                    // Пишем в файл, чтобы не терялось в агрегаторе
                                    try { File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "packet_dump.txt"), 
                                        $"Первый пакет ({data.Length} байт):\n{hex}"); } catch { }
                                    OnError?.Invoke($"🔗 Первый пакет ({data.Length} байт) — дамп сохранён в packet_dump.txt");
                                    IsConnected = true;
                                    OnConnectionChanged?.Invoke(true);
                                }

                var packet = ParsePacket(data, data.Length);
                if (packet != null)
                {
                    OnPacketReceived?.Invoke(packet);
                }
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

    public void Stop()
    {
        _cts?.Cancel();
        _readTask?.Wait(TimeSpan.FromSeconds(3));
        Dispose();
        IsConnected = false;
        OnConnectionChanged?.Invoke(false);
    }

    private static RawPacket? ParsePacket(byte[] data, int length)
    {
        if (length < 14) return null; // minimum ethernet frame

        try
        {
            var packet = new RawPacket
            {
                Timestamp = DateTime.UtcNow,
                PacketLength = length,
                PayloadRaw = data.Take(length).ToArray(),
                PayloadHex = Convert.ToHexString(data, 0, Math.Min(length, 64))
            };

            // Parse Ethernet header
            packet.SrcMac = BitConverter.ToString(data, 6, 6).Replace('-', ':');
            packet.DstMac = BitConverter.ToString(data, 0, 6).Replace('-', ':');

            int ipOffset = 14;
            if (length <= ipOffset) return packet;

            // Parse IP header
            int versionHeaderLen = data[ipOffset];
            int headerLen = (versionHeaderLen & 0x0F) * 4;

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

            // Parse TCP/UDP ports
            int transportOffset = ipOffset + headerLen;
            if (transportOffset + 4 <= length && (protocol == 6 || protocol == 17))
            {
                packet.SrcPort = (data[transportOffset] << 8) | data[transportOffset + 1];
                packet.DstPort = (data[transportOffset + 2] << 8) | data[transportOffset + 3];
            }

            // Parse TCP flags (offset 13 in TCP header)
            if (protocol == 6 && transportOffset + 14 <= length)
            {
                packet.TcpFlags = data[transportOffset + 13];
            }

            return packet;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        _udpClient?.Dispose();
        _cts?.Dispose();
    }
}
