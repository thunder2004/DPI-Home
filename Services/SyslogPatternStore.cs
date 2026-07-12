using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Persists SyslogAnalyzer's attack patterns to an editable JSON file instead of
/// hardcoding them in the app. The point: when the user (or an AI agent watching the
/// syslog feed) spots a new probe pattern that isn't caught yet, it can be added here —
/// by hand, or via the Agent API (POST /api/syslog-patterns) — and DPI-Home picks it up
/// without a rebuild or even a restart, because the file is watched for changes.
///
/// Stored next to the executable (AppContext.BaseDirectory), not in %AppData% — unlike
/// settings.json/logs (which are per-user runtime state), this is effectively a config
/// file for the app itself, and belongs alongside it so it's easy to find and edit.
/// </summary>
public static class SyslogPatternStore
{
    public static readonly string PatternsPath = Path.Combine(
        AppContext.BaseDirectory, "syslog-patterns.json");

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() } // Level as "High"/"Critical", not 3/4 — editable by hand
    };

    private static FileSystemWatcher? _watcher;
    private static DateTime _lastReloadSignal = DateTime.MinValue;
    private static readonly TimeSpan DebounceWindow = TimeSpan.FromMilliseconds(500);

    /// <summary>Fired when the file changes on disk (debounced) — callers should Load() again.</summary>
    public static event Action? OnPatternsChanged;

    /// <summary>Built-in starting set — written to disk the first time so there's something
    /// concrete to see and extend, not an empty file with no example of the shape.</summary>
    private static List<SyslogSignature> DefaultPatterns() => new()
    {
        new()
        {
            Name = "Cloud Credential File Probe", Category = "Credential Scan", Level = ThreatLevel.High,
            Description = "Request for a cloud service-account/credential file name — typical of automated bots scanning for leaked secrets",
            Patterns = new() { "firebase-credentials", "service-account", "service-account-file", "gcp-credentials", "aws-credentials", ".aws/credentials", "credentials.json", "key.json", "secrets.json" }
        },
        new()
        {
            Name = "Config/Secret File Probe", Category = "Credential Scan", Level = ThreatLevel.High,
            Description = "Request for a common secrets/config file — dotenv, SSH keys, docker/app config, VCS metadata",
            Patterns = new() { ".env", "id_rsa", ".ssh/", ".git/config", "docker-compose.yml", "appsettings.json", "wp-config.php" }
        },
        new()
        {
            Name = "Path Traversal Attempt", Category = "Web Exploit Probe", Level = ThreatLevel.Critical,
            Description = "URL contains directory traversal sequences",
            Patterns = new() { "../../", "..%2f", "%2e%2e%2f", "..\\..\\" }
        },
        new()
        {
            Name = "SQL Injection Pattern", Category = "Web Exploit Probe", Level = ThreatLevel.Critical,
            Description = "URL/query contains a classic SQL injection string",
            Patterns = new() { "union+select", "union select", "' or '1'='1", "1=1--", "sleep(" }
        },
        new()
        {
            Name = "XSS Pattern", Category = "Web Exploit Probe", Level = ThreatLevel.High,
            Description = "URL/query contains a script-injection string",
            Patterns = new() { "<script>", "javascript:", "onerror=" }
        },
        new()
        {
            Name = "Common Admin/Panel Probe", Category = "Web Recon", Level = ThreatLevel.Medium,
            Description = "Request for a common admin panel/login path unrelated to this service — typical of mass vulnerability scanners",
            Patterns = new() { "phpmyadmin", "wp-login.php", "/.well-known/security.txt", "xmlrpc.php" }
        },
    };

    /// <summary>Loads patterns from disk, seeding the file with defaults on first run.</summary>
    public static List<SyslogSignature> Load()
    {
        try
        {
            if (!File.Exists(PatternsPath))
            {
                var defaults = DefaultPatterns();
                Save(defaults);
                return defaults;
            }
            var json = File.ReadAllText(PatternsPath);
            var patterns = JsonSerializer.Deserialize<List<SyslogSignature>>(json, JsonOpts);
            return patterns ?? DefaultPatterns();
        }
        catch
        {
            // Corrupt file: fall back to defaults IN MEMORY without overwriting disk —
            // the user might want to fix a typo by hand rather than lose their edits.
            return DefaultPatterns();
        }
    }

    /// <summary>Best-effort save — disk errors must not interfere with app operation.</summary>
    public static void Save(List<SyslogSignature> patterns)
    {
        try
        {
            var dir = Path.GetDirectoryName(PatternsPath)!;
            Directory.CreateDirectory(dir);
            var json = JsonSerializer.Serialize(patterns, JsonOpts);
            File.WriteAllText(PatternsPath, json);
        }
        catch
        {
            // best-effort
        }
    }

    /// <summary>
    /// Starts watching the patterns file for external changes — e.g. the user editing it
    /// directly in a text editor, or another process writing to it — and fires
    /// OnPatternsChanged (debounced, since a single save often triggers multiple raw
    /// filesystem events) so the running app can reload without a restart.
    /// </summary>
    public static void StartWatching()
    {
        if (_watcher != null) return;
        try
        {
            var dir = Path.GetDirectoryName(PatternsPath)!;
            Directory.CreateDirectory(dir);
            _watcher = new FileSystemWatcher(dir, Path.GetFileName(PatternsPath))
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size,
                EnableRaisingEvents = true
            };
            _watcher.Changed += (_, _) => SignalChanged();
            _watcher.Created += (_, _) => SignalChanged();
        }
        catch
        {
            // best-effort — if watching fails, patterns just won't hot-reload; still
            // usable via app restart or explicitly through the Agent API.
        }
    }

    private static void SignalChanged()
    {
        var now = DateTime.UtcNow;
        if (now - _lastReloadSignal < DebounceWindow) return;
        _lastReloadSignal = now;
        OnPatternsChanged?.Invoke();
    }

    public static void StopWatching()
    {
        _watcher?.Dispose();
        _watcher = null;
    }
}
