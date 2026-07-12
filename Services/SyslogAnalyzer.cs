using System.Text.RegularExpressions;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// One attack pattern rule. Plain settable class (not a record with init-only props)
/// so it round-trips cleanly through System.Text.Json in both directions — this is what
/// gets persisted to syslog-patterns.json and what the Agent API sends/returns.
/// </summary>
public class SyslogSignature
{
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public ThreatLevel Level { get; set; } = ThreatLevel.Medium;
    public string Description { get; set; } = string.Empty;
    /// <summary>Substrings to look for, case-insensitive — plain text, not regex, so a
    /// non-programmer (or an agent) can add one without needing to know regex syntax.</summary>
    public List<string> Patterns { get; set; } = new();
}

/// <summary>
/// Scans raw syslog message text (e.g. reverse-proxy access log lines forwarded by
/// Kerio Control) for patterns typical of automated credential/exploit scanning against
/// a published web service (Exchange OWA in the case that prompted this feature, but the
/// patterns aren't Exchange-specific).
///
/// Patterns are NOT hardcoded here — they live in syslog-patterns.json
/// (see SyslogPatternStore), editable by hand or via the Agent API
/// (GET/POST /api/syslog-patterns, DELETE /api/syslog-patterns/{name}), and hot-reloaded
/// via a file watcher. This class only does the matching; MainViewModel owns the current
/// pattern list and passes it in on every call.
///
/// This is intentionally a lightweight heuristic layer, NOT a replacement for a real WAF
/// or a catalogue of Exchange CVEs (ProxyShell/ProxyNotShell etc.) — it catches the common,
/// high-volume automated scanning noise using cheap substring matching, which is exactly
/// what makes it trivial to extend without a rebuild.
/// </summary>
public static class SyslogAnalyzer
{
    // A source IP anywhere in the line. Kerio's own IP (the syslog sender) is NOT this —
    // it's the actual client IP the proxy logged, embedded in the message text itself.
    private static readonly Regex IpPattern = new(
        @"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        RegexOptions.Compiled);

    /// <summary>
    /// Analyzes one raw syslog line against the given (externally-owned, file-backed)
    /// pattern list. Returns an Alert if a pattern matched, else null. The caller is
    /// responsible for rate-limiting/aggregating (same as TrafficAnalyzer's signature
    /// path) — this method just does the pattern match and IP extraction.
    /// </summary>
    public static Alert? Analyze(string rawMessage, IReadOnlyList<SyslogSignature> signatures)
    {
        if (string.IsNullOrWhiteSpace(rawMessage)) return null;

        foreach (var sig in signatures)
        {
            foreach (var pattern in sig.Patterns)
            {
                if (string.IsNullOrEmpty(pattern)) continue;
                if (rawMessage.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    var ipMatch = IpPattern.Match(rawMessage);
                    var srcIp = ipMatch.Success ? ipMatch.Value : "unknown";

                    return new Alert
                    {
                        Timestamp = DateTime.Now,
                        Level = sig.Level,
                        Category = sig.Category,
                        Title = sig.Name,
                        ShortName = sig.Name,
                        Description = $"{sig.Description} — matched \"{pattern}\"",
                        SrcIp = srcIp,
                        Score = sig.Level switch
                        {
                            ThreatLevel.Critical => 95,
                            ThreatLevel.High => 75,
                            ThreatLevel.Medium => 50,
                            _ => 25
                        }
                    };
                }
            }
        }

        return null;
    }
}
