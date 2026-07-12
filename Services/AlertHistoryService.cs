using System.IO;
using System.Text.Json;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Persists the alert history (Event Feed cards) between launches, so closing the
/// app no longer discards everything DPI-Home has seen and blocked so far.
/// </summary>
public static class AlertHistoryService
{
    private static readonly string HistoryPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "DPI-Home", "alert-history.json");

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    /// <summary>Best-effort load. Missing/corrupt file just means "no history yet".</summary>
    public static List<AlertGroup> Load()
    {
        try
        {
            if (File.Exists(HistoryPath))
            {
                var json = File.ReadAllText(HistoryPath);
                var groups = JsonSerializer.Deserialize<List<AlertGroup>>(json, JsonOpts);
                if (groups != null) return groups;
            }
        }
        catch
        {
            // Corrupt/inaccessible file must not crash the app — start with empty history.
        }
        return new List<AlertGroup>();
    }

    /// <summary>Best-effort save — disk errors must not interfere with app operation.</summary>
    public static void Save(IEnumerable<AlertGroup> groups)
    {
        try
        {
            var dir = Path.GetDirectoryName(HistoryPath)!;
            Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(groups, JsonOpts);
            File.WriteAllText(HistoryPath, json);
        }
        catch
        {
            // best-effort
        }
    }
}
