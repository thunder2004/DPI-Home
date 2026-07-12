using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Пишет подробный лог каждого HTTP-обмена с MikroTik: метод, URL, тело запроса,
/// статус и тело ответа, полный текст исключений (ex.ToString(), а не только Message —
/// там часто теряется реальная причина вроде TLS-ошибки или отказа в соединении).
/// Нужен, потому что у нас нет прямого доступа к роутеру пользователя для отладки —
/// этот файл единственный источник истины о том, что реально ушло и что вернулось.
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

                // Простая ротация — не даём файлу расти бесконечно.
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
            // Логирование не должно ронять приложение.
        }
    }
}

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

        MikroTikDebugLog.Log($"=== Новая сессия MikroTikApiService, BaseAddress={_http.BaseAddress}, user={username} ===");
    }

    /// <summary>
    /// Создаёт адрес-лист с правилом DROP для указанного IP на 24 часа
    /// </summary>
    public async Task<string?> BlockIpAsync(string ip, string comment = "DPI-Home auto-block")
    {
        try
        {
            // 1. Проверяем, есть ли уже такой IP в списке
            var checkUrl = $"ip/firewall/address-list?address={ip}";
            MikroTikDebugLog.Log($"GET {checkUrl}");
            var checkJson = await _http.GetStringAsync(checkUrl);
            MikroTikDebugLog.Log($"  -> {checkJson}");

            var existing = JsonSerializer.Deserialize<List<MikroTikAddressList>>(checkJson, JsonOpts);
            if (existing != null && existing.Count > 0)
            {
                MikroTikDebugLog.Log($"  IP {ip} уже есть в address-list (id={existing[0].Id})");
                return $"IP {ip} уже есть в address-list (id={existing[0].Id})";
            }

            // 2. Создаём запись в address-list с timeout=1d
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
                return null; // успешно
            }

            return $"Ошибка API: {response.StatusCode} — {responseBody}";
        }
        catch (Exception ex)
        {
            MikroTikDebugLog.Log($"  EXCEPTION в BlockIpAsync: {ex}");
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
            MikroTikDebugLog.Log("GET ip/cloud");
            var json = await _http.GetStringAsync("ip/cloud");
            MikroTikDebugLog.Log($"  -> {json}");

            var cloud = JsonSerializer.Deserialize<MikroTikCloudInfo>(json, JsonOpts);
            if (cloud != null && !string.IsNullOrWhiteSpace(cloud.PublicAddress))
                return (cloud.PublicAddress, null);
            return (null, "IP Cloud не вернул public-address (служба выключена?)");
        }
        catch (Exception ex)
        {
            MikroTikDebugLog.Log($"  EXCEPTION в GetWanIpAsync: {ex}");
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
            MikroTikDebugLog.Log("GET system/identity");
            var response = await _http.GetAsync("system/identity");
            var body = await response.Content.ReadAsStringAsync();
            MikroTikDebugLog.Log($"  -> {(int)response.StatusCode} {response.StatusCode}: {body}");

            if (response.IsSuccessStatusCode)
            {
                return null; // успешно
            }
            return $"Ошибка: {response.StatusCode}";
        }
        catch (Exception ex)
        {
            MikroTikDebugLog.Log($"  EXCEPTION в TestConnectionAsync: {ex}");
            return $"Ошибка: {ex.Message}";
        }
    }

    /// <summary>
    /// Убеждается, что правило firewall для address-list существует.
    ///
    /// ВАЖНО: правильное поле для матчинга источника по address-list в правиле drop —
    /// "src-address-list" (через дефис). Раньше здесь было "address-list" в GET-запросе
    /// проверки и "address_list" (с подчёркиванием) в теле создания — оба варианта не
    /// являются валидным match-полем для action=drop в RouterOS (просто "address-list" —
    /// это параметр ДЕЙСТВИЯ add-src-to-address-list, а не критерий для drop).
    ///
    /// GET-проверка теперь фильтрует только по chain/action (базовые поля, точно
    /// поддерживаются) и фильтрует по src-address-list вручную на своей стороне —
    /// раньше проверка через query-параметр src-address-list могла быть проигнорирована
    /// роутером и вернуть чужие chain=forward action=drop правила, ошибочно считая,
    /// что наше правило уже есть.
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
                MikroTikDebugLog.Log("  Правило уже существует (найдено по src-address-list=DPI-Home-Blocked)");
                return null; // правило уже есть
            }

            // Создаём правило. Используем Dictionary, а не анонимный объект — C# не
            // разрешает дефис в имени свойства, а RouterOS ждёт именно "src-address-list".
            var payload = new Dictionary<string, object>
            {
                ["chain"] = "forward",
                ["action"] = "drop",
                ["src-address-list"] = "DPI-Home-Blocked",
                ["comment"] = "DPI-Home: блокировка подозрительных IP"
            };
            var body = JsonSerializer.Serialize(payload);
            MikroTikDebugLog.Log($"PUT ip/firewall/filter  body={body}");

            var content = new StringContent(body, Encoding.UTF8, "application/json");
            var response = await _http.PutAsync("ip/firewall/filter", content);
            var responseBody = await response.Content.ReadAsStringAsync();
            MikroTikDebugLog.Log($"  -> {(int)response.StatusCode} {response.StatusCode}: {responseBody}");

            if (response.IsSuccessStatusCode)
                return null;

            return $"Ошибка создания правила: {response.StatusCode} — {responseBody}";
        }
        catch (Exception ex)
        {
            MikroTikDebugLog.Log($"  EXCEPTION в EnsureFirewallRuleAsync: {ex}");
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

    [JsonPropertyName("src-address-list")]
    public string SrcAddressList { get; set; } = "";
}

public class MikroTikCloudInfo
{
    [JsonPropertyName("public-address")]
    public string PublicAddress { get; set; } = "";
}
