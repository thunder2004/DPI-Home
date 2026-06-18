using System.Net;
using System.Net.Sockets;
using System.Text;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Сервис захвата трафика с MikroTik через Packet Sniffer (TCP server mode)
/// MikroTik сам подключается к нам на listenPort
/// </summary>
public class MikroTikSnifferService : IDisposable
{
    private readonly int _listenPort;
    private TcpListener? _listener;
    private TcpClient? _client;
    private NetworkStream? _stream;
    private CancellationTokenSource? _cts;
    private Task? _acceptTask;
    private Task? _readTask;

    public event Action<RawPacket>? OnPacketReceived;
    public event Action<string>? OnError;
    public event Action<bool>? OnConnectionChanged;

    public bool IsConnected => _client?.Connected ?? false;
    public string ListenAddress { get; private set; } = "0.0.0.0";
    public int ListenPort => _listenPort;

    public MikroTikSnifferService(int listenPort = 2000)
    {
        _listenPort = listenPort;
    }

    public async Task StartAsync()
    {
        if (IsConnected) return;

        _cts = new CancellationTokenSource();

        try
        {
            _listener = new TcpListener(IPAddress.Any, _listenPort);
            _listener.Start();
            OnConnectionChanged?.Invoke(false);

            _acceptTask = AcceptLoopAsync(_cts.Token);
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            OnError?.Invoke($"Failed to start listener: {ex.Message}");
        }
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener != null)
        {
            try
            {
                _client = await _listener.AcceptTcpClientAsync(ct);
                _stream = _client.GetStream();
                OnConnectionChanged?.Invoke(true);

                _readTask = Task.Run(() => ReadLoopAsync(ct));
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex)
            {
                OnError?.Invoke($"Accept error: {ex.Message}");
            }
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        _readTask?.Wait(TimeSpan.FromSeconds(3));
        _acceptTask?.Wait(TimeSpan.FromSeconds(3));
        Dispose();
        OnConnectionChanged?.Invoke(false);
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[65536];

        while (!ct.IsCancellationRequested && _stream != null)
        {
            try
            {
                var bytesRead = await _stream.ReadAsync(buffer, ct);
                if (bytesRead == 0) break;

                var packet = ParsePacket(buffer, bytesRead);
                if (packet != null)
                {
                    OnPacketReceived?.Invoke(packet);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                OnError?.Invoke($"Read error: {ex.Message}");
                break;
            }
        }

        // MikroTik отключился
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
        _stream?.Dispose();
        _client?.Dispose();
        _listener?.Stop();
        _cts?.Dispose();
    }
}
