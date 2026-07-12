using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DPI_Home.Services;

/// <summary>
/// Minimal UDP syslog receiver. Deliberately does NOT try to strictly parse RFC3164/5424
/// framing (PRI, timestamp, hostname, tag) — different appliances (Kerio Control included)
/// format this inconsistently across versions, and for our purpose (spotting suspicious
/// URLs/paths in the message body) we don't actually need the structured fields, just the
/// raw text. Every received datagram is decoded as UTF-8 and handed off whole; the caller
/// (SyslogAnalyzer) regex-searches the raw text for an IP address and suspicious patterns.
/// </summary>
public class SyslogListenerService : IDisposable
{
    private UdpClient? _udpClient;
    private CancellationTokenSource? _cts;
    private Task? _readTask;

    public int Port { get; }
    public bool IsRunning { get; private set; }

    public event Action<string>? OnMessageReceived;
    public event Action<string>? OnError;
    public event Action<bool>? OnRunningChanged;

    public SyslogListenerService(int port)
    {
        Port = port;
    }

    public Task StartAsync()
    {
        if (_udpClient != null) return Task.CompletedTask;

        try
        {
            _udpClient = new UdpClient(Port);
            _cts = new CancellationTokenSource();
            IsRunning = true;
            OnRunningChanged?.Invoke(true);
            OnError?.Invoke($"✅ Syslog listener started on UDP {Port}");
            _readTask = ReadLoopAsync(_cts.Token);
        }
        catch (Exception ex)
        {
            OnError?.Invoke($"❌ Syslog listener failed to start on UDP {Port}: {ex.Message}");
            _udpClient = null;
            IsRunning = false;
            OnRunningChanged?.Invoke(false);
        }

        return Task.CompletedTask;
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _udpClient != null)
        {
            try
            {
                var result = await _udpClient.ReceiveAsync(ct);
                var text = Encoding.UTF8.GetString(result.Buffer);
                OnMessageReceived?.Invoke(text);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (Exception ex)
            {
                OnError?.Invoke($"⚠️ Syslog read error: {ex.Message}");
            }
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
        IsRunning = false;
        OnRunningChanged?.Invoke(false);
    }

    public void Dispose() => Stop();
}
