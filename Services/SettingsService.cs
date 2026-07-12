using System.IO;
using System.Text.Json;

namespace DPI_Home.Services;

/// <summary>
/// Application settings persisted between launches.
/// Password is NOT persisted — enter it each session.
/// </summary>
public class AppSettings
{
    public string MikrotikHost { get; set; } = "192.168.105.1";
    public string MikrotikUser { get; set; } = "admin";
    public string WanIp { get; set; } = "";
    public bool AutoBlockEnabled { get; set; }
    public int ListenPort { get; set; } = 37008;
    public int RdpThreshold { get; set; } = 3;
    public int RdpWindowSeconds { get; set; } = 300;
    /// <summary>API key for the Agent API (GET /api/blocks, DELETE /api/blocks/{ip}).</summary>
    public string AgentApiKey { get; set; } = "";
}

public static class SettingsService
{
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "DPI-Home", "settings.json");

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                var settings = JsonSerializer.Deserialize<AppSettings>(json);
                if (settings != null) return settings;
            }
        }
        catch
        {
            // Corrupt/inaccessible settings file must not crash the app —
            // just start with defaults as if no settings existed yet.
        }
        return new AppSettings();
    }

    /// <summary>Save — best-effort, disk errors must not interfere with app operation.</summary>
    public static void Save(AppSettings settings)
    {
        try
        {
            var dir = Path.GetDirectoryName(SettingsPath)!;
            Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(settings, JsonOpts);
            File.WriteAllText(SettingsPath, json);
        }
        catch
        {
            // best-effort
        }
    }
}