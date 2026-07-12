using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Сервис для управления MikroTik через REST API (RouterOS 7+)
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

        _http = new HttpClient
        {
            BaseAddress = new Uri($"https://{host}/rest/"),
            Timeout = TimeSpan.FromSeconds(10)
        };

        var auth = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{username}:{password}"));
        _http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);
        // Отключаем проверку SSL (самоподписанный сертификат MikroTik)
        ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    }

    /// <summary>
    /// Создаёт адрес-лист с правилом DROP для указанного IP на 24 часа
    /// </summary>
    public async Task<string?> BlockIpAsync(string ip, string comment = "DPI-Home auto-block")
    {
        try
        {
            // 1. Проверяем, есть ли уже такой IP в списке
            var checkJson = await _http.GetStringAsync($"ip/firewall/address-list?address={ip}");
            var existing = JsonSerializer.Deserialize<List<MikroTikAddressList>>(checkJson, JsonOpts);
            if (existing != null && existing.Count > 0)
            {
                return $"IP {ip} уже есть в address-list (id={existing[0].Id})";
            }

            // 2. Создаём запись в address-list с timeout=1d
            var expires = DateTime.UtcNow.AddDays(1);
            var payload = new
            {
                address = ip,
                list = "DPI-Home-Blocked",
                timeout = "1d",
                comment = comment
            };

            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await _http.PutAsync("ip/firewall/address-list", content);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                return null; // успешно
            }

            return $"Ошибка API: {response.StatusCode} — {responseBody}";
        }
        catch (Exception ex)
        {
            return $"Ошибка: {ex.Message}";
        }
    }

    /// <summary>
    /// Определяет публичный (WAN) IP роутера через IP Cloud (RouterOS "/ip cloud").
    /// Без этого IP NetworkContext не может классифицировать трафик, адресованный на наш
    /// публичный адрес, как "наш" — такие пакеты получают Direction=Unknown и полностью
    /// выпадают из детекта (в том числе SYN Flood на проброшенные из WAN сервисы).
    /// Требует, чтобы служба IP Cloud была включена на роутере (/ip cloud set ddns-enabled=yes
    /// или хотя бы просто включена сама служба — public-address заполняется в любом случае).
    /// </summary>
    public async Task<(string? Ip, string? Error)> GetWanIpAsync()
    {
        try
        {
            var json = await _http.GetStringAsync("ip/cloud");
            var cloud = JsonSerializer.Deserialize<MikroTikCloudInfo>(json, JsonOpts);
            if (cloud != null && !string.IsNullOrWhiteSpace(cloud.PublicAddress))
                return (cloud.PublicAddress, null);
            return (null, "IP Cloud не вернул public-address (служба выключена?)");
        }
        catch (Exception ex)
        {
            return (null, $"Ошибка: {ex.Message}");
        }
    }

    /// <summary>
    /// Проверяет подключение к MikroTik
    /// </summary>
    public async Task<string?> TestConnectionAsync()
    {
        try
        {
            var response = await _http.GetAsync("system/identity");
            if (response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                return null; // успешно
            }
            return $"Ошибка: {response.StatusCode}";
        }
        catch (Exception ex)
        {
            return $"Ошибка: {ex.Message}";
        }
    }

    /// <summary>
    /// Убеждается, что правило firewall для address-list существует
    /// </summary>
    public async Task<string?> EnsureFirewallRuleAsync()
    {
        try
        {
            var rulesJson = await _http.GetStringAsync("ip/firewall/filter?chain=forward&action=drop&address-list=DPI-Home-Blocked");
            var existing = JsonSerializer.Deserialize<List<MikroTikFirewallRule>>(rulesJson, JsonOpts);
            if (existing != null && existing.Count > 0)
            {
                return null; // правило уже есть
            }

            // Создаём правило
            var payload = new
            {
                chain = "forward",
                action = "drop",
                address_list = "DPI-Home-Blocked",
                comment = "DPI-Home: блокировка подозрительных IP"
            };

            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await _http.PutAsync("ip/firewall/filter", content);

            if (response.IsSuccessStatusCode)
                return null;

            var err = await response.Content.ReadAsStringAsync();
            return $"Ошибка создания правила: {err}";
        }
        catch (Exception ex)
        {
            return $"Ошибка: {ex.Message}";
        }
    }
}

public class MikroTikAddressList
{
    public string Id { get; set; } = "";
    public string Address { get; set; } = "";
    public string List { get; set; } = "";
    public string Timeout { get; set; } = "";
}

public class MikroTikFirewallRule
{
    public string Id { get; set; } = "";
    public string Chain { get; set; } = "";
    public string Action { get; set; } = "";
    public string AddressList { get; set; } = "";
}

public class MikroTikCloudInfo
{
    [JsonPropertyName("public-address")]
    public string PublicAddress { get; set; } = "";
}