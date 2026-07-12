using System.Text.RegularExpressions;
using DPI_Home.Models;

namespace DPI_Home.Services;

public record SyslogSignature
{
    public string Name { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public ThreatLevel Level { get; init; } = ThreatLevel.Medium;
    public string Description { get; init; } = string.Empty;
    /// <summary>Substring to look for, case-insensitive. Kept as plain substrings rather than
    /// regex for this first version — easy for a non-programmer to extend later.</summary>
    public string[] Patterns { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Scans raw syslog message text (e.g. reverse-proxy access log lines forwarded by
/// Kerio Control) for patterns typical of automated credential/exploit scanning against
/// a published web service (Exchange OWA in the case that prompted this feature, but the
/// patterns aren't Exchange-specific).
///
/// This is intentionally a lightweight heuristic layer, NOT a replacement for a real WAF
/// or a catalogue of Exchange CVEs (ProxyShell/ProxyNotShell etc.) — it catches the common,
/// high-volume automated scanning noise (bots probing for leaked cloud credential files,
/// path traversal, SQLi/XSS strings, known secret file names) using cheap substring matching
/// so it's trivially extensible without needing to understand the underlying exploit.
/// </summary>
public static class SyslogAnalyzer
{
    // A source IP anywhere in the line. Kerio's own IP (the syslog sender) is NOT this —
    // it's the actual client IP the proxy logged, embedded in the message text itself.
    private static readonly Regex IpPattern = new(
        @"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        RegexOptions.Compiled);

    private static readonly List<SyslogSignature> Signatures = new()
    {
        new()
        {
            Name = "Cloud Credential File Probe",
            Category = "Credential Scan",
            Level = ThreatLevel.High,
            Description = "Request for a cloud service-account/credential file name — typical of automated bots scanning for leaked secrets",
            Patterns = new[]
            {
                "firebase-credentials", "service-account", "service-account-file",
                "gcp-credentials", "aws-credentials", ".aws/credentials",
                "credentials.json", "key.json", "secrets.json"
            }
        },
        new()
        {
            Name = "Config/Secret File Probe",
            Category = "Credential Scan",
            Level = ThreatLevel.High,
            Description = "Request for a common secrets/config file — dotenv, SSH keys, docker/app config, VCS metadata",
            Patterns = new[]
            {
                ".env", "id_rsa", ".ssh/", ".git/config", "docker-compose.yml",
                "appsettings.json", "wp-config.php"
            }
        },
        new()
        {
            Name = "Path Traversal Attempt",
            Category = "Web Exploit Probe",
            Level = ThreatLevel.Critical,
            Description = "URL contains directory traversal sequences",
            Patterns = new[] { "../../", "..%2f", "%2e%2e%2f", "..\\..\\" }
        },
        new()
        {
            Name = "SQL Injection Pattern",
            Category = "Web Exploit Probe",
            Level = ThreatLevel.Critical,
            Description = "URL/query contains a classic SQL injection string",
            Patterns = new[] { "union+select", "union select", "' or '1'='1", "1=1--", "sleep(" }
        },
        new()
        {
            Name = "XSS Pattern",
            Category = "Web Exploit Probe",
            Level = ThreatLevel.High,
            Description = "URL/query contains a script-injection string",
            Patterns = new[] { "<script>", "javascript:", "onerror=" }
        },
        new()
        {
            Name = "Common Admin/Panel Probe",
            Category = "Web Recon",
            Level = ThreatLevel.Medium,
            Description = "Request for a common admin panel/login path unrelated to this service — typical of mass vulnerability scanners",
            Patterns = new[] { "phpmyadmin", "wp-login.php", "/.well-known/security.txt", "xmlrpc.php" }
        },
    };

    /// <summary>
    /// Analyzes one raw syslog line. Returns an Alert if a signature matched, else null.
    /// The caller is responsible for rate-limiting/aggregating (same as TrafficAnalyzer's
    /// signature path) — this method just does the pattern match and IP extraction.
    /// </summary>
    public static Alert? Analyze(string rawMessage)
    {
        if (string.IsNullOrWhiteSpace(rawMessage)) return null;

        foreach (var sig in Signatures)
        {
            foreach (var pattern in sig.Patterns)
            {
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
