using System.IO;
using System.Text.Json;

namespace DPI_Home.Services;

/// <summary>
/// Настройки приложения, сохраняемые между запусками.
///
/// ВАЖНО: MikrotikPassword хранится в открытом виде (plain text) в JSON-файле
/// в профиле пользователя. Это осознанный компромисс для домашнего инструмента —
/// не используйте сюда пароль, который важен где-то ещё, и учитывайте, что
/// любой процесс с доступом к вашему профилю Windows сможет его прочитать.
/// </summary>
public class AppSettings
{
    public string MikrotikHost { get; set; } = "192.168.105.1";
    public string MikrotikUser { get; set; } = "admin";
    public string MikrotikPassword { get; set; } = "";
    public string WanIp { get; set; } = "";
    public bool AutoBlockEnabled { get; set; }
    public int ListenPort { get; set; } = 37008;
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
            // Повреждённый/недоступный файл настроек не должен ронять приложение —
            // просто стартуем с дефолтами, как будто настроек ещё не было.
        }
        return new AppSettings();
    }

    /// <summary>Сохранение — best-effort, ошибки диска не должны мешать работе приложения.</summary>
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
