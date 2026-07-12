using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using DPI_Home.Models;
using DPI_Home.ViewModels;

namespace DPI_Home.Services;

/// <summary>
/// Agent API for AI agents to query blocked IPs, analyze blocks, and unblock false positives.
/// Runs as a lightweight HTTP server (HttpListener, stdlib — no Kestrel needed).
/// </summary>
public class AgentApiService : IDisposable
{
    private readonly HttpListener _listener;
    private readonly MainViewModel _vm;
    private readonly string _apiKey;
    private CancellationTokenSource? _cts;
    private Task? _listenTask;

    private const int Port = 37409;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public AgentApiService(MainViewModel vm, string apiKey)
    {
        _vm = vm;
        _apiKey = apiKey;
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
    }

    /// <summary>
    /// Starts the HTTP listener. Must be called after Application.Current is available
    /// (e.g. from Window.Loaded), otherwise OnError() dispatcher will be null.
    /// </summary>
    public string Start()
    {
        _cts = new CancellationTokenSource();
        _listener.Start();
        _listenTask = Task.Run(() => Listen(_cts.Token));
        return $"🚀 Agent API listening on http://127.0.0.1:{Port} — key: {_apiKey}";
    }

    public void Stop()
    {
        _cts?.Cancel();
        _listener.Stop();
    }

    private async Task Listen(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var ctx = await _listener.GetContextAsync().WaitAsync(ct);
                _ = Task.Run(() => Handle(ctx), ct);
            }
            catch (OperationCanceledException) { break; }
            catch (HttpListenerException) { break; }
            catch { /* ignore transient errors */ }
        }
    }

    private async void Handle(HttpListenerContext ctx)
    {
        // Auth
        if (!_apiKey.Equals(ctx.Request.Headers["X-API-Key"] ?? "", StringComparison.Ordinal))
        {
            ctx.Response.StatusCode = 401;
            var bytes = Encoding.UTF8.GetBytes("{\"error\":\"Unauthorized\"}");
            ctx.Response.Close(bytes, true);
            return;
        }

        var path = ctx.Request.Url?.AbsolutePath ?? "/";
        var method = ctx.Request.HttpMethod;

        string response;
        int statusCode;

        try
        {
            (response, statusCode) = path switch
            {
                "/api/blocks" when method == "GET" => (await GetBlocks(), 200),
                "/api/blocks" when method == "POST" => (await CreateBlock(ctx), 200),
                "/api/blocks" when method == "DELETE" => (await DeleteAllBlocks(ctx), 200),

                var p when p.StartsWith("/api/blocks/") && method == "DELETE" =>
                    (await DeleteBlock(ctx, p["/api/blocks/".Length..]), 200),

                "/api/alerts" when method == "GET" => (GetAlerts(), 200),

                var p when p == "/api/status" && method == "GET" => (GetStatus(), 200),

                "/api/capture/start" when method == "POST" => (await StartCapture(), 200),
                "/api/capture/stop" when method == "POST" => (StopCapture(), 200),

                "/api/autoblock" when method == "POST" => (await SetAutoBlock(ctx), 200),
                "/api/wanip" when method == "POST" => (await SetWanIp(ctx), 200),
                "/api/rdp-settings" when method == "POST" => (await SetRdpSettings(ctx), 200),
                "/api/excluded-ports" when method == "POST" => (await SetExcludedPorts(ctx), 200),

                _ => ("{\"error\":\"Not Found\"}", 404)
            };
        }
        catch (Exception ex)
        {
            response = JsonSerializer.Serialize(new { error = ex.Message });
            statusCode = 500;
        }

        ctx.Response.StatusCode = statusCode;
        ctx.Response.ContentType = "application/json";
        try
        {
            await ctx.Response.OutputStream.WriteAsync(Encoding.UTF8.GetBytes(response));
            ctx.Response.Close();
        }
        catch
        {
            // Client disconnected mid-response or similar transient I/O error.
            // Handle() is async void (required by HttpListener's callback shape),
            // so an unhandled exception here would propagate uncaught and could
            // crash the app — never let a single client's connection issue do that.
        }
    }

    private async Task<string> GetBlocks()
    {
        if (_vm.MikrotikApi == null || !_vm.MikrotikConnected)
            return JsonSerializer.Serialize(new { error = "MikroTik not connected" });

        try
        {
            var json = await _vm.MikrotikApi.FetchAddressListAsync("DPI-Home-Blocked");
            var entries = JsonSerializer.Deserialize<List<MikroTikAddressList>>(json ?? "[]", JsonOpts)
                         ?? new List<MikroTikAddressList>();

            return JsonSerializer.Serialize(new
            {
                blocked = entries.Select(e => new BlockedIpInfo
                {
                    Ip = e.Address,
                    List = e.List,
                    Timeout = e.Timeout,
                    Comment = e.Comment,
                    CreatedAt = e.CreatedAt
                }).ToList(),
                total = entries.Count
            });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message });
        }
    }

    private async Task<string> DeleteBlock(HttpListenerContext ctx, string ip)
    {
        if (_vm.MikrotikApi == null || !_vm.MikrotikConnected)
            return JsonSerializer.Serialize(new { error = "MikroTik not connected" });

        if (string.IsNullOrWhiteSpace(ip))
            return JsonSerializer.Serialize(new { error = "IP required" });

        ip = Uri.UnescapeDataString(ip);
        var err = await _vm.MikrotikApi.UnblockIpAsync(ip);
        if (err == null)
            return JsonSerializer.Serialize(new { unblocked = ip, success = true });

        // Already absent is OK — treat as success
        if (err.Contains("not in DPI-Home-Blocked", StringComparison.OrdinalIgnoreCase))
            return JsonSerializer.Serialize(new { unblocked = ip, success = true, note = err });

        return JsonSerializer.Serialize(new { unblocked = ip, success = false, error = err });
    }

    private async Task<string> DeleteAllBlocks(HttpListenerContext ctx)
    {
        if (_vm.MikrotikApi == null || !_vm.MikrotikConnected)
            return JsonSerializer.Serialize(new { error = "MikroTik not connected" });

        using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
        var body = await reader.ReadToEndAsync();
        var payload = JsonSerializer.Deserialize<UnblockAllRequest>(body, JsonOpts);

        if (payload?.Confirm != true)
            return JsonSerializer.Serialize(new { error = "confirm=true required" });

        try
        {
            var json = await _vm.MikrotikApi.FetchAddressListAsync("DPI-Home-Blocked");
            var entries = JsonSerializer.Deserialize<List<MikroTikAddressList>>(json ?? "[]", JsonOpts)
                         ?? new List<MikroTikAddressList>();

            var results = new List<object>();
            foreach (var e in entries)
            {
                var err = await _vm.MikrotikApi.UnblockIpAsync(e.Address);
                results.Add(new { ip = e.Address, success = err == null, error = err });
            }

            return JsonSerializer.Serialize(new { unblocked = results, total = entries.Count });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message });
        }
    }

    private async Task<string> CreateBlock(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
        var body = await reader.ReadToEndAsync();
        var payload = JsonSerializer.Deserialize<BlockRequest>(body, JsonOpts);

        if (string.IsNullOrWhiteSpace(payload?.Ip))
            return JsonSerializer.Serialize(new { error = "ip required" });

        if (_vm.MikrotikApi == null)
            return JsonSerializer.Serialize(new { error = "MikroTik not connected" });

        var reason = string.IsNullOrWhiteSpace(payload.Reason)
            ? $"DPI-Home agent-api block {DateTime.Now:yyyy-MM-dd HH:mm}"
            : payload.Reason;

        // BlockIp only touches MikroTik over the network and adds to the alert
        // aggregator (which already dispatches to the UI thread internally via
        // OnAlertGroup) — safe to await directly from this background thread.
        await _vm.BlockIp(payload.Ip, reason);
        return JsonSerializer.Serialize(new { blocked = payload.Ip, reason });
    }

    private async Task<string> StartCapture()
    {
        // StartAsync() toggles: if already connected it would STOP capture instead.
        // Guard explicitly so a POST /api/capture/start is never accidentally a stop.
        bool alreadyRunning = RunOnUiThread(() => _vm.IsConnected);
        if (alreadyRunning)
            return JsonSerializer.Serialize(new { started = false, note = "already running" });

        await RunOnUiThreadAsync(() => _vm.StartAsync());
        return JsonSerializer.Serialize(new { started = true });
    }

    private string StopCapture()
    {
        bool wasRunning = RunOnUiThread(() =>
        {
            if (!_vm.IsConnected) return false;
            _vm.Stop();
            return true;
        });
        return JsonSerializer.Serialize(new { stopped = wasRunning });
    }

    private async Task<string> SetAutoBlock(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
        var body = await reader.ReadToEndAsync();
        var payload = JsonSerializer.Deserialize<AutoBlockRequest>(body, JsonOpts);

        RunOnUiThread(() => _vm.AutoBlockEnabled = payload?.Enabled ?? false);
        return JsonSerializer.Serialize(new { autoBlock = _vm.AutoBlockEnabled });
    }

    private async Task<string> SetWanIp(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
        var body = await reader.ReadToEndAsync();
        var payload = JsonSerializer.Deserialize<WanIpRequest>(body, JsonOpts);

        if (string.IsNullOrWhiteSpace(payload?.Ip))
            return JsonSerializer.Serialize(new { error = "ip required" });

        RunOnUiThread(() =>
        {
            _vm.WanIp = payload.Ip;
            _vm.ApplyWanIpManual();
        });
        return JsonSerializer.Serialize(new { wanIp = _vm.WanIp });
    }

    private async Task<string> SetRdpSettings(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
        var body = await reader.ReadToEndAsync();
        var payload = JsonSerializer.Deserialize<RdpSettingsRequest>(body, JsonOpts);

        if (payload == null)
            return JsonSerializer.Serialize(new { error = "invalid body" });

        RunOnUiThread(() =>
        {
            if (payload.Threshold > 0) _vm.RdpThreshold = payload.Threshold;
            if (payload.WindowMinutes > 0) _vm.RdpWindowMinutes = payload.WindowMinutes;
        });
        return JsonSerializer.Serialize(new { rdpThreshold = _vm.RdpThreshold, rdpWindowMinutes = _vm.RdpWindowMinutes });
    }

    /// <summary>Excludes ports (e.g. a torrent client's) from SYN Flood / Port Scan detection —
    /// legitimate swarm traffic (many peers, one fixed port) is otherwise numerically
    /// indistinguishable from a flood.</summary>
    private async Task<string> SetExcludedPorts(HttpListenerContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
        var body = await reader.ReadToEndAsync();
        var payload = JsonSerializer.Deserialize<ExcludedPortsRequest>(body, JsonOpts);

        if (payload?.Ports == null)
            return JsonSerializer.Serialize(new { error = "ports required (array of int)" });

        RunOnUiThread(() =>
        {
            _vm.ExcludedPortsText = string.Join(",", payload.Ports);
            _vm.ApplyExcludedPorts();
        });
        return JsonSerializer.Serialize(new { excludedPorts = payload.Ports });
    }

    /// <summary>
    /// Marshals a mutation onto the UI thread. Required for anything that touches a
    /// WPF-bound property or ObservableCollection: this API server runs handlers on
    /// thread-pool threads, but WPF's binding system throws if a bound property is
    /// changed (i.e. PropertyChanged raised) from a non-UI thread.
    /// </summary>
    private static void RunOnUiThread(Action action) =>
        Application.Current.Dispatcher.Invoke(action);

    private static T RunOnUiThread<T>(Func<T> func) =>
        Application.Current.Dispatcher.Invoke(func);

    /// <summary>Same as RunOnUiThread but for an async operation started on the UI thread.</summary>
    private static Task RunOnUiThreadAsync(Func<Task> action) =>
        Application.Current.Dispatcher.InvokeAsync(action).Task.Unwrap();

    private string GetAlerts()
    {
        var alerts = _vm.AlertGroups
            .OrderByDescending(g => g.LastSeen)
            .Take(100)
            .Select(g => new AlertSummary
            {
                Ip = g.SrcIp,
                Level = g.MaxLevel.ToString(),
                LevelIcon = g.LevelIcon,
                FirstSeen = g.FirstSeen,
                LastSeen = g.LastSeen,
                EventCount = g.TotalCount,
                AttackTypes = g.AttackTypes,
                Categories = g.Categories
                    .Select(c => new CategoryInfo
                    {
                        Name = c.Key,
                        Count = c.Value.Count,
                        Ports = c.Value.Ports.ToList()
                    }).ToList()
            }).ToList();

        return JsonSerializer.Serialize(new
        {
            alerts,
            total = alerts.Count,
            tip = "To unblock: DELETE /api/blocks/{ip}"
        });
    }

    private string GetStatus()
    {
        return JsonSerializer.Serialize(new
        {
            connected = _vm.IsConnected,
            mikrotik = _vm.MikrotikConnected,
            wanIp = _vm.WanIp,
            stats = _vm.Stats,
            autoBlock = _vm.AutoBlockEnabled,
            listenPort = _vm.ListenPort,
            rdpThreshold = _vm.RdpThreshold,
            rdpWindowMinutes = _vm.RdpWindowMinutes,
            httpsClients = _vm.HttpsServerCount,
            httpsEstablished = _vm.HttpsEstablishedCount,
            alertsTotal = _vm.AlertGroups.Count
        });
    }

    public void Dispose()
    {
        Stop();
        _cts?.Dispose();
    }
}

// ── DTOs ────────────────────────────────────────────────────────────────────

public class BlockedIpInfo
{
    public string Ip { get; set; } = "";
    public string List { get; set; } = "";
    public string Timeout { get; set; } = "";
    public string Comment { get; set; } = "";
    public DateTime? CreatedAt { get; set; }
}

public class AlertSummary
{
    public string Ip { get; set; } = "";
    public string Level { get; set; } = "";
    public string LevelIcon { get; set; } = "";
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public long EventCount { get; set; }
    public string AttackTypes { get; set; } = "";
    public List<CategoryInfo> Categories { get; set; } = new();
}

public class CategoryInfo
{
    public string Name { get; set; } = "";
    public int Count { get; set; }
    public List<int> Ports { get; set; } = new();
}

public class UnblockAllRequest
{
    [JsonPropertyName("confirm")]
    public bool Confirm { get; set; }
}

public class BlockRequest
{
    public string Ip { get; set; } = "";
    public string? Reason { get; set; }
}

public class AutoBlockRequest
{
    public bool Enabled { get; set; }
}

public class WanIpRequest
{
    public string Ip { get; set; } = "";
}

public class RdpSettingsRequest
{
    public int Threshold { get; set; }
    public int WindowMinutes { get; set; }
}

public class ExcludedPortsRequest
{
    public List<int> Ports { get; set; } = new();
}
