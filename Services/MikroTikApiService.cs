using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Logs every HTTP exchange with MikroTik in detail: method, URL, request body,
/// status and response body, full exception text (ex.ToString(), not just Message —
/// the real cause like a TLS error or connection refusal is often lost otherwise).
/// Needed because we don't have direct access to the user's router for debugging —
/// this file is the single source of truth for what was actually sent and returned.
/// </summary>
public static class MikroTikDebugLog
{
    public static readonly string LogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "DPI-Home", "mikrotik-debug.log");

    private static readonly object Lock = new();

    public static void Log(string message)
    {
        try
        {
            lock (Lock)
            {
                var dir = Path.GetDirectoryName(LogPath)!;
                Directory.CreateDirectory(dir);
                var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}";
                File.AppendAllText(LogPath, line);

                // Simple rotation — prevent unbounded file growth.
                var info = new FileInfo(LogPath);
                if (info.Exists && info.Length > 2_000_000)
                {
                    var lines = File.ReadAllLines(LogPath);
                    File.WriteAllLines(LogPath, lines[Math.Max(0, lines.Length - 2000)..]);
                }
            }
        }
        catch
        {
            // Logging must never crash the app.
        }
    }
}

/// <summary>
/// Service for managing MikroTik via REST API (RouterOS 7+)
/// </summary>
public class MikroTikApiService
{
    private readonly string _host;
    private readonly string _username;
    private readonly string _password;
    private readonly HttpClient _http;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public MikroTikApiService(string host, string username, string password)
    {
        _host = host;
        _username = username;
        _password = password;

        // IMPORTANT: previously used ServicePointManager.ServerCertificateValidationCallback —
        // this is a legacy API that does NOT work with HttpClient in modern .NET (Core/5+)
        // (SocketsHttpHandler is under the hood, not the old ServicePoint stack). Bypassing
        // MikroTik's self-signed certificate is done via HttpClientHandler — the only method
        // that actually works for HttpClient in current .NET.
        //
        // Also explicitly pin TLS 1.2: RouterOS TLS stack often only supports it,
        // and .NET defaults to negotiating TLS 1.3/system cipher suites which sometimes
        // fail — hence the intermittent "HandshakeFailure" connection attempts.
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            SslProtocols = SslProtocols.Tls12
        };

        _http = new HttpClient(handler)
        {
            BaseAddress = new Uri($"https://{host}/rest/"),
            Timeout = TimeSpan.FromSeconds(10)
        };

        var auth = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{username}:{password}"));
        _http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);

        MikroTikDebugLog.Log($"=== New MikroTikApiService session, BaseAddress={_http.BaseAddress}, user={username}, TLS=1.2 (forced) ===");
    }

    /// <summary>
    /// Removes an IP from the DPI-Home-Blocked address-list on MikroTik.
    /// </summary>
    public async Task<string?> UnblockIpAsync(string ip)
    {
        try
        {
            var listUrl = "ip/firewall/address-list?list=DPI-Home-Blocked";
            MikroTikDebugLog.Log($"GET {listUrl}");
            var json = await _http.GetStringAsync(listUrl);
            MikroTikDebugLog.Log($"  -> {json}");

            var entries = JsonSerializer.Deserialize<List<MikroTikAddressList>>(json, JsonOpts);
            var entry = entries?.FirstOrDefault(e => e.Address == ip);
            if (entry == null)
            {
                MikroTikDebugLog.Log($"  IP {ip} not found in DPI-Home-Blocked");
                return $"IP {ip} not in DPI-Home-Blocked";
            }

            MikroTikDebugLog.Log($"DELETE ip/firewall/address-list/{entry.Id}");
            var response = await _http.DeleteAsync($"ip/firewall/address-list/{entry.Id}");
            var body = await response.Content.ReadAsStringAsync();
            MikroTikDebugLog.Log($"  -> {(int)response.StatusCode}: {body}");

            if (response.IsSuccessStatusCode)
                return null;
            return $"API error: {response.StatusCode} — {body}";
        }
        catch (Exception ex)
        {
            MikroTikDebugLog.Log($"  EXCEPTION in UnblockIpAsync: {ex}");
            return $"Error: {ex.Message}";
        }
    }

    /// <summary>
    /// Fetches the raw JSON of the address-list entries for the given list name.
    /// Used by AgentApiService to enumerate blocked IPs.
    /// </summary>
    public async Task<string?> FetchAddressListAsync(string listName)
    {
        try
        {
            var url = $"ip/firewall/address-list?list={Uri.EscapeDataString(listName)}";
            MikroTikDebugLog.Log($"GET {url}");
            var json = await _http.GetStringAsync(url);
            MikroTikDebugLog.Log($"  -> {json}");
            return json;
        }
        catch (Exception ex)
        {
            MikroTikDebugLog.Log($"  EXCEPTION in FetchAddressListAsync: {ex}");
            return null;
        }
    }

    /// <summary>
    /// Creates an address-list entry with a DROP rule for the specified IP for 24 hours
    /// </summary>
    public async Task<string?> BlockIpAsync(string ip, string comment = "DPI-Home auto-block")
    {
        try
        {
            // 1. Check if this IP is already in the list
            var checkUrl = $"ip/firewall/address-list?address={ip}";
            MikroTikDebugLog.Log($"GET {checkUrl}");
            var checkJson = await _http.GetStringAsync(checkUrl);
            MikroTikDebugLog.Log($"  -> {checkJson}");

            var existing = JsonSerializer.Deserialize<List<MikroTikAddressList>>(checkJson, JsonOpts);
            // ponytail: filter by list name — IP may be in Home_net or other lists,
            // which doesn't mean it's already in DPI-Home-Blocked. Without this check,
            // blocking was silently skipped for any IP already in any address-list.
            var alreadyBlocked = existing?.FirstOrDefault(e => e.List == "DPI-Home-Blocked");
            if (alreadyBlocked != null)
            {
                MikroTikDebugLog.Log($"  IP {ip} already in DPI-Home-Blocked (id={alreadyBlocked.Id})");
                return $"IP {ip} already in DPI-Home-Blocked (id={alreadyBlocked.Id})";
            }

            // 2. Create address-list entry with timeout=1d
            var payload = new
            {
                address = ip,
                list = "DPI-Home-Blocked",
                timeout = "1d",
                comment = comment
            };
            var body = JsonSerializer.Serialize(payload);
            MikroTikDebugLog.Log($"PUT ip/firewall/address-list  body={body}");

            var content = new StringContent(body, Encoding.UTF8, "application/json");
            var response = await _http.PutAsync("ip/firewall/address-list", content);
            var responseBody = await response.Content.ReadAsStringAsync();
            MikroTikDebugLog.Log($"  -> {(int)response.StatusCode} {response.StatusCode}: {responseBody}");

            if (response.IsSuccessStatusCode)
            {
                return null; // success
            }

            return $"API error: {response.StatusCode} — {responseBody}";
        }
        catch (Exception ex)
        {
            MikroTikDebugLog.Log($"  EXCEPTION in BlockIpAsync: {ex}");
            return $"Error: {ex.Message}";
        }
    }

    /// <summary>
    /// Retrieves the router's public (WAN) IP via IP Cloud (RouterOS "/ip cloud").
    /// Without this IP, NetworkContext cannot classify traffic addressed to our
    /// public address as "ours" — such packets get Direction=Unknown and completely
    /// fall out of detection (including SYN Flood on port-forwarded WAN services).
    /// Requires IP Cloud service enabled on the router (/ip cloud set ddns-enabled=yes
    /// or at least the service itself enabled — public-address is populated regardless).
    /// </summary>
    public async Task<(string? Ip, string? Error)> GetWanIpAsync()
    {
        try
        {
            MikroTikDebugLog.Log("GET ip/cloud");
            var json = await _http.GetStringAsync("ip/cloud");
            MikroTikDebugLog.Log($"  -> {json}");

            var cloud = JsonSerializer.Deserialize<MikroTikCloudInfo>(json, JsonOpts);
            if (cloud != null && !string.IsNullOrWhiteSpace(cloud.PublicAddress))
                return (cloud.PublicAddress, null);
            return (null, "IP Cloud did not return public-address (service disabled?)");
        }
        catch (Exception ex)
        {
            MikroTikDebugLog.Log($"  EXCEPTION in GetWanIpAsync: {ex}");
            return (null, $"Error: {ex.Message}");
        }
    }

    /// <summary>
    /// Tests connection to MikroTik
    /// </summary>
    public async Task<string?> TestConnectionAsync()
    {
        try
        {
            MikroTikDebugLog.Log("GET system/identity");
            var response = await _http.GetAsync("system/identity");
            var body = await response.Content.ReadAsStringAsync();
            MikroTikDebugLog.Log($"  -> {(int)response.StatusCode} {response.StatusCode}: {body}");

            if (response.IsSuccessStatusCode)
            {
                return null; // success
            }
            return $"Error: {response.StatusCode}";
        }
        catch (Exception ex)
        {
            MikroTikDebugLog.Log($"  EXCEPTION in TestConnectionAsync: {ex}");
            return $"Error: {ex.Message}";
        }
    }

    /// <summary>
    /// Ensures the firewall rule for the address-list exists.
    ///
    /// IMPORTANT: the correct field for matching source by address-list in a drop rule is
    /// "src-address-list" (with hyphen). Previously "address-list" was used in the GET
    /// check and "address_list" (underscore) in the create body — neither is a valid
    /// match field for action=drop in RouterOS ("address-list" is a parameter of the
    /// add-src-to-address-list action, not a drop criterion).
    ///
    /// The GET check now filters only by chain/action (base fields, definitely supported)
    /// and filters by src-address-list manually on our side — previously the query-parameter
    /// src-address-list could be ignored by the router and return foreign chain=forward
    /// action=drop rules, falsely concluding our rule already exists.
    /// </summary>
    public async Task<string?> EnsureFirewallRuleAsync()
    {
        try
        {
            MikroTikDebugLog.Log("GET ip/firewall/filter?chain=forward&action=drop");
            var rulesJson = await _http.GetStringAsync("ip/firewall/filter?chain=forward&action=drop");
            MikroTikDebugLog.Log($"  -> {rulesJson}");

            var existing = JsonSerializer.Deserialize<List<MikroTikFirewallRule>>(rulesJson, JsonOpts);
            if (existing != null && existing.Any(r => r.SrcAddressList == "DPI-Home-Blocked"))
            {
                MikroTikDebugLog.Log("  Rule already exists (found by src-address-list=DPI-Home-Blocked)");
                return null; // rule already exists
            }

            // Create rule. Using Dictionary, not anonymous object — C# doesn't
            // allow hyphens in property names, and RouterOS expects "src-address-list".
            var payload = new Dictionary<string, object>
            {
                ["chain"] = "forward",
                ["action"] = "drop",
                ["src-address-list"] = "DPI-Home-Blocked",
                ["comment"] = "DPI-Home: block suspicious IPs"
            };
            var body = JsonSerializer.Serialize(payload);
            MikroTikDebugLog.Log($"PUT ip/firewall/filter  body={body}");

            var content = new StringContent(body, Encoding.UTF8, "application/json");
            var response = await _http.PutAsync("ip/firewall/filter", content);
            var responseBody = await response.Content.ReadAsStringAsync();
            MikroTikDebugLog.Log($"  -> {(int)response.StatusCode} {response.StatusCode}: {responseBody}");

            if (response.IsSuccessStatusCode)
                return null;

            return $"Rule creation error: {response.StatusCode} — {responseBody}";
        }
        catch (Exception ex)
        {
            MikroTikDebugLog.Log($"  EXCEPTION in EnsureFirewallRuleAsync: {ex}");
            return $"Error: {ex.Message}";
        }
    }
}

public class MikroTikAddressList
{
    public string Id { get; set; } = "";
    public string Address { get; set; } = "";
    public string List { get; set; } = "";
    public string Timeout { get; set; } = "";
    public string Comment { get; set; } = "";

    [JsonPropertyName("created-at")]
    public DateTime? CreatedAt { get; set; }
}

public class MikroTikFirewallRule
{
    public string Id { get; set; } = "";
    public string Chain { get; set; } = "";
    public string Action { get; set; } = "";

    [JsonPropertyName("src-address-list")]
    public string SrcAddressList { get; set; } = "";
}

public class MikroTikCloudInfo
{
    [JsonPropertyName("public-address")]
    public string PublicAddress { get; set; } = "";
}