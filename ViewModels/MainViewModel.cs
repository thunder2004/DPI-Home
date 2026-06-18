using System.Collections.ObjectModel;
using System.ComponentModel;
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
    private readonly AlertAggregator _aggregator;
    private readonly DispatcherTimer _statsTimer;
    private readonly object _httpsLock = new();

    private TrafficStats _stats = new();
    private bool _isConnected;
    private string _connectionStatus = "Ожидание пакетов от MikroTik...";
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
            ConnectionStatus = value ? "✅ Получаю пакеты от MikroTik" : "⏳ Ожидание пакетов от MikroTik...";
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

    public bool MikrotikConnected
    {
        get => _mikrotikConnected;
        set { _mikrotikConnected = value; OnPropertyChanged(); }
    }

    public ICommand StartCommand { get; }
    public ICommand StopCommand { get; }
    public ICommand ClearLogCommand { get; }
    public ICommand ConnectMikrotikCommand { get; }
        public ICommand BlockIpCommand { get; }

        public MainViewModel()
    {
        StartCommand = new AsyncRelayCommand(StartAsync);
        StopCommand = new RelayCommand(Stop);
        ClearLogCommand = new RelayCommand(ClearLog);
        ConnectMikrotikCommand = new AsyncRelayCommand(ConnectMikrotikAsync);
        BlockIpCommand = new AsyncRelayCommand<string>(BlockIp);

        _sniffer = CreateSniffer();
        _analyzer = new TrafficAnalyzer();
        _aggregator = new AlertAggregator();

        _analyzer.OnAlert += OnAlert;
        _aggregator.OnAlertGroup += OnAlertGroup;
        _analyzer.OnHttpsServerGroupUpdate += OnHttpsServerGroupUpdate;

        _statsTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _statsTimer.Tick += UpdateStats;
        _statsTimer.Start();
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
    /// Подключение к MikroTik REST API
    /// </summary>
    public async Task ConnectMikrotikAsync()
    {
        try
        {
            _mikrotikApi = new MikroTikApiService(_mikrotikHost, _mikrotikUser, _mikrotikPassword);
            var error = await _mikrotikApi.TestConnectionAsync();

            if (error == null)
            {
                // Проверяем/создаём правило firewall
                var fwError = await _mikrotikApi.EnsureFirewallRuleAsync();
                if (fwError != null)
                {
                    OnError($"⚠️ MikroTik API: правило не создано: {fwError}");
                }

                MikrotikConnected = true;
                OnError($"✅ MikroTik API: подключено к {_mikrotikHost}");
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

    /// <summary>
    /// Блокировка выбранного IP на MikroTik через address-list
    /// </summary>
    public async Task BlockIp(string? ip)
        {
            if (string.IsNullOrEmpty(ip) || _mikrotikApi == null)
            {
                OnError("⚠️ Сначала подключись к MikroTik");
                return;
            }

            await Application.Current.Dispatcher.Invoke(async () =>
            {
                var error = await _mikrotikApi.BlockIpAsync(ip, $"DPI-Home auto-block {DateTime.Now:yyyy-MM-dd HH:mm}");
            if (error == null)
            {
                var alert = new Alert
                {
                    Timestamp = DateTime.Now,
                    Level = ThreatLevel.High,
                    Category = "MikroTik",
                    Title = "IP заблокирован на MikroTik",
                    Description = $"IP {ip} добавлен в address-list DPI-Home-Blocked на 24ч",
                    SrcIp = ip,
                    Score = 0
                };
                _aggregator.Add(alert);
            }
            else
            {
                OnError($"❌ Блокировка IP {ip}: {error}");
            }
        });
    }

    private void OnPacketReceived(RawPacket packet)
    {
        Interlocked.Increment(ref _packetCounter);
        _analyzer.Analyze(packet);
    }

    private void OnAlert(Alert alert)
    {
        _aggregator.Add(alert);
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

    private void OnError(string error)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            var alert = new Alert
            {
                Timestamp = DateTime.Now,
                Level = ThreatLevel.High,
                Category = "System",
                Title = "Система",
                Description = error,
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
}