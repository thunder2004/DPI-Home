using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;

namespace DPI_Home.Services;

/// <summary>One raw syslog line, whether or not it matched a known attack pattern.</summary>
public class SyslogMessageEntry
{
    public DateTime Timestamp { get; set; }
    public string RawMessage { get; set; } = string.Empty;
    public bool Matched { get; set; }
    public string? PatternName { get; set; }
}

/// <summary>
/// Keeps a queryable record of every raw syslog line DPI-Home has received — not just the
/// ones that matched a known attack pattern. The point: an agent looking for NEW patterns
/// needs to see the traffic that DIDN'T match anything yet (that's exactly where new
/// patterns come from), not just confirmed alerts. Exposed via the Agent API
/// (GET /api/syslog-messages) so an agent doesn't need to know where any file lives on
/// disk or how the app is laid out — it just calls the endpoint.
/// </summary>
public static class SyslogMessageStore
{
    private const int MaxInMemory = 1000;
    private static readonly ConcurrentQueue<SyslogMessageEntry> Buffer = new();

    // Runtime data (not config), so %AppData% like the other logs/settings — separate
    // file from mikrotik-debug.log so it's not mixed in with unrelated MikroTik HTTP
    // traffic and stays easy for a script/agent to parse (JSON Lines: one object per line).
    private static readonly string LogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "DPI-Home", "syslog-messages.log");

    private static readonly object FileLock = new();
    private static readonly JsonSerializerOptions JsonOpts = new();

    /// <summary>Records one raw syslog line — in the in-memory buffer (fast API reads) and
    /// appended to a JSON-Lines file on disk (durable across restarts).</summary>
    public static void Add(SyslogMessageEntry entry)
    {
        Buffer.Enqueue(entry);
        while (Buffer.Count > MaxInMemory)
            Buffer.TryDequeue(out _);

        try
        {
            lock (FileLock)
            {
                var dir = Path.GetDirectoryName(LogPath)!;
                Directory.CreateDirectory(dir);
                var line = JsonSerializer.Serialize(entry, JsonOpts);
                File.AppendAllText(LogPath, line + Environment.NewLine);

                // Same rotation approach as MikroTikDebugLog — don't let this grow forever.
                var info = new FileInfo(LogPath);
                if (info.Exists && info.Length > 5_000_000)
                {
                    var lines = File.ReadAllLines(LogPath);
                    File.WriteAllLines(LogPath, lines[Math.Max(0, lines.Length - 5000)..]);
                }
            }
        }
        catch
        {
            // best-effort — the in-memory buffer (and thus the Agent API) still works
            // even if the disk write fails.
        }
    }

    /// <summary>Most recent entries, newest first. unmatchedOnly=true returns only the ones
    /// that didn't trip a known pattern — exactly what's useful for spotting new probes.</summary>
    public static List<SyslogMessageEntry> GetRecent(int limit = 100, bool unmatchedOnly = false)
    {
        IEnumerable<SyslogMessageEntry> items = Buffer.ToArray().Reverse();
        if (unmatchedOnly) items = items.Where(e => !e.Matched);
        return items.Take(limit).ToList();
    }
}
