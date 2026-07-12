using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
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

    public void Start()
    {
        _cts = new CancellationTokenSource();
        _listener.Start();
        _listenTask = Task.Run(() => Listen(_cts.Token));

        // Log startup to UI
        _vm.OnError($"🚀 Agent API listening on http://127.0.0.1:{Port}");
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
                "/api/blocks" when method == "DELETE" => (await DeleteAllBlocks(ctx), 200),

                var p when p.StartsWith("/api/blocks/") && method == "DELETE" =>
                    (await DeleteBlock(ctx, p["/api/blocks/".Length..]), 200),

                "/api/alerts" when method == "GET" => (GetAlerts(), 200),

                var p when p == "/api/status" && method == "GET" => (GetStatus(), 200),

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
        await ctx.Response.OutputStream.WriteAsync(Encoding.UTF8.GetBytes(response));
        ctx.Response.Close();
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
