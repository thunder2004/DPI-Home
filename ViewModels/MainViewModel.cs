using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.Input;
using DPI_Home.Models;
using DPI_Home.Services;

namespace DPI_Home.ViewModels;

public class MainViewModel : INotifyPropertyChanged
{
    private MikroTikSnifferService _sniffer;
    private readonly TrafficAnalyzer _analyzer;
    private readonly NetworkContext _netCtx;
    private readonly AlertAggregator _aggregator;
    private readonly DispatcherTimer _statsTimer;
    private readonly object _httpsLock = new();
    private AgentApiService? _agentApi;
    private string _agentApiKey = "";
    private bool _apiConnected;

    private TrafficStats _stats = new();
    private bool _isConnected;
    private string _connectionStatus = "Waiting for packets from MikroTik...";
    private string _statusColor = "#FF9800";
    private int _listenPort = 37008;
    private long _packetCounter;
    private int _httpsServerCount;
    private int _httpsEstablishedCount;
    private int _httpsSynFloodCount;

    // MikroTik API settings
    private string _mikrotikHost = "192.168.105.1";
    private string _mikrotikUser = "admin";
    private string _mikrotikPassword = "";
    private bool _mikrotikConnected;
    private MikroTikApiService? _mikrotikApi;

    // WAN IP (router public address). Without it NetworkContext cannot distinguish
    // "our public service" from foreign traffic — all inbound to our WAN-IP
    // gets Direction=Unknown and never reaches detectors (incl. SYN Flood).
    // Populated automatically on MikroTik connect (via IP Cloud) or manually.
    private string _wanIp = "";

    // Auto-block: on Critical/High alert with reliable (non-spoofed) SrcIp,
    // automatically adds it to the DPI-Home-Blocked address-list on MikroTik.
    private bool _autoBlockEnabled;
    private readonly ConcurrentDictionary<string, DateTime> _autoBlockAttempts = new();
    private static readonly TimeSpan AutoBlockCooldown = TimeSpan.FromHours(24); // matches MikroTik block duration

    public ObservableCollection<AlertGroup> AlertGroups { get; } = new();
    public ObservableCollection<HttpsServerGroup> HttpsServerGroups { get; } = new();

    public TrafficStats Stats
    {
        get => _stats;
        set { _stats = value; OnPropertyChanged(); }
    }

    public bool IsConnected
    {
        get => _isConnected;
        set
        {
            _isConnected = value;
            OnPropertyChanged();
            ConnectionStatus = value ? "✅ Receiving packets from MikroTik" : "⏳ Waiting for packets from MikroTik...";
            StatusColor = value ? "#4CAF50" : "#FF9800";
        }
    }

    public string ConnectionStatus
    {
        get => _connectionStatus;
        set { _connectionStatus = value; OnPropertyChanged(); }
    }

    public string StatusColor
    {
        get => _statusColor;
        set { _statusColor = value; OnPropertyChanged(); }
    }

    public int ListenPort
    {
        get => _listenPort;
        set { _listenPort = value; OnPropertyChanged(); }
    }

    public int HttpsServerCount
    {
        get => _httpsServerCount;
        set { _httpsServerCount = value; OnPropertyChanged(); }
    }

    public int HttpsEstablishedCount
    {
        get => _httpsEstablishedCount;
        set { _httpsEstablishedCount = value; OnPropertyChanged(); }
    }

    public int HttpsSynFloodCount
    {
        get => _httpsSynFloodCount;
        set { _httpsSynFloodCount = value; OnPropertyChanged(); }
    }

    // MikroTik API properties
    public string MikrotikHost
    {
        get => _mikrotikHost;
        set { _mikrotikHost = value; OnPropertyChanged(); }
    }

    public string MikrotikUser
    {
        get => _mikrotikUser;
        set { _mikrotikUser = value; OnPropertyChanged(); }
    }

    public string MikrotikPassword
    {
        get => _mikrotikPassword;
        set { _mikrotikPassword = value; OnPropertyChanged(); }
    }

    public MikroTikApiService? MikrotikApi => _mikrotikApi;

    public bool MikrotikConnected
    {
        get => _mikrotikConnected;
        set { _mikrotikConnected = value; OnPropertyChanged(); }
    }

    public string WanIp
    {
        get => _wanIp;
        set { _wanIp = value; OnPropertyChanged(); }
    }

    public bool AutoBlockEnabled
    {
        get => _autoBlockEnabled;
        set { _autoBlockEnabled = value; OnPropertyChanged(); SaveSettings(); }
    }

    private int _rdpThreshold = 3;
    public int RdpThreshold
    {
        get => _rdpThreshold;
        set { _rdpThreshold = value; OnPropertyChanged(); _analyzer.RdpThreshold = value; SaveSettings(); }
    }

    private int _rdpWindowMinutes = 5;
    public int RdpWindowMinutes
    {
        get => _rdpWindowMinutes;
        set { _rdpWindowMinutes = value; OnPropertyChanged(); _analyzer.RdpWindowSeconds = value * 60; SaveSettings(); }
    }

    public string AgentApiKey => _agentApiKey;

    public bool ApiConnected
    {
        get => _apiConnected;
        private set { _apiConnected = value; OnPropertyChanged(); }
    }

    /// <summary>Start the Agent API and log the URL+key to the UI alert panel.</summary>
    public void StartApi()
    {
        if (_agentApi == null) return;
        var msg = _agentApi.Start();
        ApiConnected = true;
        OnError(msg);
    }

    public ICommand StartCommand { get; }
    public ICommand StopCommand { get; }
    public ICommand ClearLogCommand { get; }
    public ICommand ConnectMikrotikCommand { get; }
    public ICommand ApplyWanIpCommand { get; }
    public ICommand OpenDebugLogCommand { get; }
    public ICommand CopyApiKeyCommand { get; }
    public ICommand BlockIpCommand { get; }

    public MainViewModel()
    {
        StartCommand = new AsyncRelayCommand(StartAsync);
        StopCommand = new RelayCommand(Stop);
        ClearLogCommand = new RelayCommand(ClearLog);
        ConnectMikrotikCommand = new AsyncRelayCommand(ConnectMikrotikAsync);
        ApplyWanIpCommand = new RelayCommand(ApplyWanIpManual);
        OpenDebugLogCommand = new RelayCommand(OpenDebugLog);
        CopyApiKeyCommand = new RelayCommand(CopyApiKey);
        BlockIpCommand = new AsyncRelayCommand<string>(ip => BlockIp(ip));

        // Load saved settings (MikroTik, WAN-IP, auto-block) — best-effort,
        // on missing/corrupt file just stay on defaults.
        var settings = SettingsService.Load();
        _mikrotikHost = settings.MikrotikHost;
        _mikrotikUser = settings.MikrotikUser;
        _listenPort = settings.ListenPort;
        _autoBlockEnabled = settings.AutoBlockEnabled;
        _rdpThreshold = settings.RdpThreshold;
        _rdpWindowMinutes = settings.RdpWindowSeconds / 60;

        _sniffer = CreateSniffer();

        // Network context: our subnets + WAN-IP. Without WAN-IP, packets addressed to our
        // public address get Direction=Unknown and never reach detectors —
        // WAN-IP is populated automatically on MikroTik connect (see ConnectMikrotikAsync)
        // or manually via WanIp/ApplyWanIpCommand, and also restored from settings.
        _netCtx = NetworkContext.CreateDefault();
        _netCtx.Vantage = NetworkContext.CaptureVantage.Wan;
        if (!string.IsNullOrWhiteSpace(settings.WanIp))
        {
            _netCtx.AddWanIp(settings.WanIp);
            _wanIp = settings.WanIp;
        }
        _analyzer = new TrafficAnalyzer(_netCtx);
        // Packet-flow debug log (every 100 packets) goes to the debug output, not the
        // user-facing alert feed — routing it through OnError previously mixed harmless
        // "[DEBUG] [PKT] Total: N ..." noise into the same list as real security alerts.
        _analyzer.OnDebugLog += msg => System.Diagnostics.Debug.WriteLine(msg);
        _analyzer.RdpThreshold = _rdpThreshold;
        _analyzer.RdpWindowSeconds = _rdpWindowMinutes * 60;
        _aggregator = new AlertAggregator();

        _analyzer.OnAlert += OnAlert;
        _aggregator.OnAlertGroup += OnAlertGroup;
        _analyzer.OnHttpsServerGroupUpdate += OnHttpsServerGroupUpdate;

        // Load or generate the Agent API key. Reuses the settings instance already
        // loaded above instead of reading settings.json a second time.
        if (string.IsNullOrWhiteSpace(settings.AgentApiKey))
        {
            settings.AgentApiKey = GenerateApiKey();
            SettingsService.Save(settings);
        }
        _agentApi = new AgentApiService(this, settings.AgentApiKey);
        _agentApiKey = settings.AgentApiKey;

        _statsTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _statsTimer.Tick += UpdateStats;
        _statsTimer.Start();
    }

    /// <summary>Copies the Agent API key to the clipboard.</summary>
    private void CopyApiKey()
    {
        if (string.IsNullOrEmpty(_agentApiKey)) return;
        try
        {
            Clipboard.SetText(_agentApiKey);
            OnError("📋 API key copied to clipboard");
        }
        catch (Exception ex)
        {
            OnError($"⚠️ Failed to copy API key: {ex.Message}");
        }
    }

    /// <summary>Opens the detailed HTTP exchange log with MikroTik (creates it if it doesn't exist).</summary>
    private void OpenDebugLog()
    {
        try
        {
            var path = MikroTikDebugLog.LogPath;
            var dir = Path.GetDirectoryName(path)!;
            Directory.CreateDirectory(dir);
            if (!File.Exists(path))
                File.WriteAllText(path, "Log is empty — perform an action with MikroTik (connect, block) to see entries here.\r\n");

            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            OnError($"⚠️ Failed to open log: {ex.Message}");
        }
    }

    /// <summary>Collects and saves current settings to disk (best-effort).</summary>
    private void SaveSettings()
    {
        SettingsService.Save(new AppSettings
        {
            MikrotikHost = _mikrotikHost,
            MikrotikUser = _mikrotikUser,
            WanIp = _wanIp,
            AutoBlockEnabled = _autoBlockEnabled,
            ListenPort = _listenPort,
            RdpThreshold = _rdpThreshold,
            RdpWindowSeconds = _rdpWindowMinutes * 60
        });
    }

    private MikroTikSnifferService CreateSniffer()
    {
        var s = new MikroTikSnifferService(_listenPort);
        s.OnPacketReceived += OnPacketReceived;
        s.OnError += OnError;
        s.OnConnectionChanged += OnConnectionChanged;
        return s;
    }

    public async Task StartAsync()
    {
        if (IsConnected)
        {
            Stop();
            return;
        }

        _sniffer = CreateSniffer();
        await _sniffer.StartAsync();
    }

    public void Stop()
    {
        _sniffer.Stop();
        IsConnected = false;
    }

    public void ClearLog()
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            _aggregator.FlushAll();
            AlertGroups.Clear();
        });
    }

    /// <summary>
    /// Connect to MikroTik REST API
    /// </summary>
    public async Task ConnectMikrotikAsync()
    {
        try
        {
            _mikrotikApi = new MikroTikApiService(_mikrotikHost, _mikrotikUser, _mikrotikPassword);
            var error = await _mikrotikApi.TestConnectionAsync();

            if (error == null)
            {
                // Check/create firewall rule
                var fwError = await _mikrotikApi.EnsureFirewallRuleAsync();
                if (fwError != null)
                {
                    OnError($"⚠️ MikroTik API: rule not created: {fwError}");
                }

                MikrotikConnected = true;
                OnError($"✅ MikroTik API: connected to {_mikrotikHost}");

                // Auto-detect WAN-IP via IP Cloud. Without it, all traffic addressed to our
                // public address (e.g. attack on a port-forwarded WAN service),
                // is classified as Direction=Unknown and never reaches detectors.
                var (wanIp, wanErr) = await _mikrotikApi.GetWanIpAsync();
                if (wanIp != null)
                {
                    _netCtx.AddWanIp(wanIp);
                    WanIp = wanIp;
                    OnError($"🌐 WAN-IP auto-detected: {wanIp} — detection now covers inbound traffic to this address");
                }
                else
                {
                    OnError($"⚠️ Could not auto-detect WAN-IP ({wanErr}). Enter it manually in the WAN IP field, otherwise inbound attacks on the public address won't be detected");
                }

                SaveSettings();
            }
            else
            {
                MikrotikConnected = false;
                OnError($"❌ MikroTik API: {error}");
            }
        }
        catch (Exception ex)
        {
            MikrotikConnected = false;
            OnError($"❌ MikroTik API: {ex.Message}");
        }
    }

    /// <summary>Manual WAN-IP application (fallback if IP Cloud is unavailable/disabled on router).</summary>
    public void ApplyWanIpManual()
    {
        if (string.IsNullOrWhiteSpace(_wanIp))
        {
            OnError("⚠️ Enter a WAN-IP before applying");
            return;
        }

        _netCtx.AddWanIp(_wanIp.Trim());
        OnError($"🌐 WAN-IP applied manually: {_wanIp.Trim()} — detection now covers inbound traffic to this address");
        SaveSettings();
    }

    /// <summary>
    /// Block IP on MikroTik via address-list DPI-Home-Blocked (already linked
    /// to a drop rule in the forward chain, created on MikroTik connect).
    ///
    /// Previously the network call was wrapped in "await Application.Current.Dispatcher.Invoke(async () => {...})" —
    /// this is a classic trap: Dispatcher.Invoke with Func&lt;Task&gt; returns the OUTER Task (the fact
    /// the delegate started), not the Task of its completion, so await returned before the block
    /// was actually applied on MikroTik. The network call doesn't need to run on the UI thread — here it
    /// is just awaited directly; UI updates as usual via _aggregator.Add(alert) (which already
    /// has its own correct Dispatcher.Invoke inside OnAlertGroup).
    /// </summary>
    public async Task BlockIp(string? ip, string? reason = null)
    {
        if (string.IsNullOrEmpty(ip) || _mikrotikApi == null)
        {
            OnError("⚠️ Connect to MikroTik first");
            return;
        }

        var comment = reason ?? $"DPI-Home manual block {DateTime.Now:yyyy-MM-dd HH:mm}";
        var error = await _mikrotikApi.BlockIpAsync(ip, comment);

        if (error == null)
        {
            var alert = new Alert
            {
                Timestamp = DateTime.Now,
                Level = ThreatLevel.High,
                Category = "MikroTik",
                Title = "IP blocked on MikroTik",
                Description = $"IP {ip} added to address-list DPI-Home-Blocked for 24h ({comment})",
                SrcIp = ip,
                Score = 0
            };
            _aggregator.Add(alert);
        }
        else
        {
            OnError($"❌ Block IP {ip}: {error}");
        }
    }

    /// <summary>
    /// Auto-block: triggers on Critical/High alerts with reliable SrcIp.
    /// Spoofed SYN Flood (Alert.Spoofed=true) is intentionally skipped — under spoofing,
    /// SrcIp may belong to an innocent bystander, not the attacker,
    /// and blocking such IP won't stop the attack but may harm the innocent.
    /// </summary>
    private void TryAutoBlock(Alert alert)
    {
        if (!AutoBlockEnabled) return;
        if (_mikrotikApi == null || !MikrotikConnected) return;
        if (alert.Spoofed) return;
        if (alert.Level is not (ThreatLevel.Critical or ThreatLevel.High)) return;
        if (string.IsNullOrEmpty(alert.SrcIp) || alert.SrcIp == "system") return;
        if (_netCtx.IsLocal(alert.SrcIp)) return; // safety: never block our own network
        if (_netCtx.IsWellKnown(alert.SrcIp)) return; // DNS resolvers, CDN, NTP — alert shown but not blocked

        var now = DateTime.UtcNow;
        if (_autoBlockAttempts.TryGetValue(alert.SrcIp, out var last) && now - last < AutoBlockCooldown)
            return; // already attempted recently for this IP — don't spam the API on every repeat trigger
        _autoBlockAttempts[alert.SrcIp] = now;

        _ = BlockIp(alert.SrcIp, $"DPI-Home auto-block: {alert.Category} ({DateTime.Now:yyyy-MM-dd HH:mm})");
    }

    private void OnPacketReceived(RawPacket packet)
    {
        Interlocked.Increment(ref _packetCounter);
        _analyzer.Analyze(packet);
    }

    private void OnAlert(Alert alert)
    {
        _aggregator.Add(alert);
        TryAutoBlock(alert);
    }

    private void OnAlertGroup(AlertGroup group)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            var existing = AlertGroups.FirstOrDefault(g => g.GroupKey == group.GroupKey);
            if (existing != null)
            {
                var idx = AlertGroups.IndexOf(existing);
                AlertGroups[idx] = group;
            }
            else
            {
                AlertGroups.Insert(0, group);
            }

            while (AlertGroups.Count > 200)
                AlertGroups.RemoveAt(AlertGroups.Count - 1);
        });
    }

    private void OnHttpsServerGroupUpdate(HttpsServerGroup group)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            lock (_httpsLock)
            {
                bool isActive = group.EstablishedCount > 0 || group.SynSentCount > 0;

                var existing = HttpsServerGroups.FirstOrDefault(g => g.DstIp == group.DstIp);
                if (existing != null)
                {
                    if (isActive)
                    {
                        var idx = HttpsServerGroups.IndexOf(existing);
                        HttpsServerGroups[idx] = group;
                    }
                    else
                    {
                        HttpsServerGroups.Remove(existing);
                    }
                }
                else if (isActive)
                {
                    HttpsServerGroups.Insert(0, group);
                }

                while (HttpsServerGroups.Count > 200)
                    HttpsServerGroups.RemoveAt(HttpsServerGroups.Count - 1);
            }
        });
    }

    public void OnError(string error)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            var alert = new Alert
            {
                Timestamp = DateTime.Now,
                Level = ThreatLevel.Info,
                Category = "System",
                Title = "System",
                ShortName = "ℹ️ System",
                Description = error,
                SrcIp = "system",
                Score = 0
            };
            _aggregator.Add(alert);
        });
    }

    private void OnConnectionChanged(bool connected)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            IsConnected = connected;
        });
    }

    private void UpdateStats(object? sender, EventArgs e)
    {
        Stats = new TrafficStats
        {
            TotalPackets = Interlocked.Read(ref _packetCounter),
            AlertsToday = (int)AlertGroups.Sum(g => g.TotalCount),
            AlertsCritical = AlertGroups.Count(g => g.MaxLevel == ThreatLevel.Critical),
            AlertsHigh = AlertGroups.Count(g => g.MaxLevel == ThreatLevel.High),
            AlertsMedium = AlertGroups.Count(g => g.MaxLevel == ThreatLevel.Medium),
        };

        HttpsServerCount = HttpsServerGroups.Count;
        HttpsEstablishedCount = HttpsServerGroups.Sum(g => g.EstablishedCount);
        HttpsSynFloodCount = AlertGroups.Sum(g => g.Categories.ContainsKey("SYN Flood") ? g.Categories["SYN Flood"].Count : 0);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }

    private static string GenerateApiKey()
    {
        // Note: 32 bytes = 43 base64 chars, URL-safe. Good enough for an API key.
        var bytes = new byte[32];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-").Replace("/", "_").TrimEnd('=');
    }
}