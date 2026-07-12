using System.Collections.Concurrent;
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
    private readonly NetworkContext _netCtx;
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

    // WAN IP (публичный адрес роутера). Без него NetworkContext не может отличить
    // "наш публичный сервис" от постороннего трафика — весь инбаунд на наш WAN-IP
    // получает Direction=Unknown и не доходит до детекторов (в т.ч. SYN Flood).
    // Заполняется автоматически при подключении к MikroTik (через IP Cloud) либо вручную.
    private string _wanIp = "";

    // Автоблокировка: при срабатывании Critical/High алерта с надёжным (не спуфленным)
    // SrcIp автоматически добавляет его в address-list DPI-Home-Blocked на MikroTik.
    private bool _autoBlockEnabled;
    private readonly ConcurrentDictionary<string, DateTime> _autoBlockAttempts = new();
    private static readonly TimeSpan AutoBlockCooldown = TimeSpan.FromHours(24); // совпадает со сроком блокировки на MikroTik

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

    public ICommand StartCommand { get; }
    public ICommand StopCommand { get; }
    public ICommand ClearLogCommand { get; }
    public ICommand ConnectMikrotikCommand { get; }
    public ICommand ApplyWanIpCommand { get; }
        public ICommand BlockIpCommand { get; }

        public MainViewModel()
    {
        StartCommand = new AsyncRelayCommand(StartAsync);
        StopCommand = new RelayCommand(Stop);
        ClearLogCommand = new RelayCommand(ClearLog);
        ConnectMikrotikCommand = new AsyncRelayCommand(ConnectMikrotikAsync);
        ApplyWanIpCommand = new RelayCommand(ApplyWanIpManual);
        BlockIpCommand = new AsyncRelayCommand<string>(ip => BlockIp(ip));

        // Загружаем сохранённые настройки (MikroTik, WAN-IP, автоблок) — best-effort,
        // при отсутствии/повреждении файла просто остаёмся на дефолтах.
        var settings = SettingsService.Load();
        _mikrotikHost = settings.MikrotikHost;
        _mikrotikUser = settings.MikrotikUser;
        _mikrotikPassword = settings.MikrotikPassword;
        _listenPort = settings.ListenPort;
        _autoBlockEnabled = settings.AutoBlockEnabled;

        _sniffer = CreateSniffer();

        // Контекст сети: свои подсети + WAN-IP. Без WAN-IP пакеты, адресованные на наш
        // публичный адрес, получают Direction=Unknown и не доходят до детекторов —
        // WAN-IP подставляется автоматически при подключении к MikroTik (см. ConnectMikrotikAsync)
        // либо вручную через WanIp/ApplyWanIpCommand, а также восстанавливается из настроек.
        _netCtx = NetworkContext.CreateDefault();
        _netCtx.Vantage = NetworkContext.CaptureVantage.Wan;
        if (!string.IsNullOrWhiteSpace(settings.WanIp))
        {
            _netCtx.AddWanIp(settings.WanIp);
            _wanIp = settings.WanIp;
        }
        _analyzer = new TrafficAnalyzer(_netCtx);
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

    /// <summary>Собирает и сохраняет текущие настройки на диск (best-effort).</summary>
    private void SaveSettings()
    {
        SettingsService.Save(new AppSettings
        {
            MikrotikHost = _mikrotikHost,
            MikrotikUser = _mikrotikUser,
            MikrotikPassword = _mikrotikPassword,
            WanIp = _wanIp,
            AutoBlockEnabled = _autoBlockEnabled,
            ListenPort = _listenPort
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

                // Автоопределение WAN-IP через IP Cloud. Без него весь трафик, адресованный
                // на наш публичный адрес (например, атака на проброшенный из WAN сервис),
                // классифицируется как Direction=Unknown и не доходит до детекторов.
                var (wanIp, wanErr) = await _mikrotikApi.GetWanIpAsync();
                if (wanIp != null)
                {
                    _netCtx.AddWanIp(wanIp);
                    WanIp = wanIp;
                    OnError($"🌐 WAN-IP определён автоматически: {wanIp} — детект теперь покрывает входящий трафик на этот адрес");
                }
                else
                {
                    OnError($"⚠️ Не удалось определить WAN-IP автоматически ({wanErr}). Введите его вручную в поле WAN IP, иначе входящие атаки на публичный адрес не будут обнаруживаться");
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

    /// <summary>Ручное применение WAN-IP (фолбэк, если IP Cloud недоступен/выключен на роутере).</summary>
    public void ApplyWanIpManual()
    {
        if (string.IsNullOrWhiteSpace(_wanIp))
        {
            OnError("⚠️ Введите WAN-IP перед применением");
            return;
        }

        _netCtx.AddWanIp(_wanIp.Trim());
        OnError($"🌐 WAN-IP применён вручную: {_wanIp.Trim()} — детект теперь покрывает входящий трафик на этот адрес");
        SaveSettings();
    }

    /// <summary>
    /// Блокировка IP на MikroTik через address-list DPI-Home-Blocked (уже привязан
    /// к правилу drop в forward-цепочке, созданному при подключении к MikroTik).
    ///
    /// Раньше сетевой вызов был обёрнут в "await Application.Current.Dispatcher.Invoke(async () => {...})" —
    /// это классическая ловушка: Dispatcher.Invoke с Func&lt;Task&gt; возвращает ВНЕШНИЙ Task (сам факт
    /// запуска делегата), а не Task его завершения, поэтому await отрабатывал раньше, чем реально
    /// проходила блокировка на MikroTik. Сетевой вызов не обязан выполняться на UI-потоке — здесь он
    /// просто await-ится напрямую; UI обновляется как обычно через _aggregator.Add(alert) (там уже
    /// есть свой корректный Dispatcher.Invoke внутри OnAlertGroup).
    /// </summary>
    public async Task BlockIp(string? ip, string? reason = null)
    {
        if (string.IsNullOrEmpty(ip) || _mikrotikApi == null)
        {
            OnError("⚠️ Сначала подключись к MikroTik");
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
                Title = "IP заблокирован на MikroTik",
                Description = $"IP {ip} добавлен в address-list DPI-Home-Blocked на 24ч ({comment})",
                SrcIp = ip,
                Score = 0
            };
            _aggregator.Add(alert);
        }
        else
        {
            OnError($"❌ Блокировка IP {ip}: {error}");
        }
    }

    /// <summary>
    /// Автоблокировка: срабатывает на Critical/High алертах с надёжным SrcIp.
    /// Спуфленные SYN Flood (Alert.Spoofed=true) пропускаются намеренно — при спуфинге
    /// SrcIp может принадлежать случайному постороннему адресу, а не атакующему,
    /// и блокировка такого IP не остановит атаку, зато может навредить невиновному.
    /// </summary>
    private void TryAutoBlock(Alert alert)
    {
        if (!AutoBlockEnabled) return;
        if (_mikrotikApi == null || !MikrotikConnected) return;
        if (alert.Spoofed) return;
        if (alert.Level is not (ThreatLevel.Critical or ThreatLevel.High)) return;
        if (string.IsNullOrEmpty(alert.SrcIp) || alert.SrcIp == "system") return;
        if (_netCtx.IsLocal(alert.SrcIp)) return; // подстраховка: свою же сеть никогда не блокируем

        var now = DateTime.UtcNow;
        if (_autoBlockAttempts.TryGetValue(alert.SrcIp, out var last) && now - last < AutoBlockCooldown)
            return; // уже пытались недавно для этого IP — не спамим API на каждое повторное срабатывание
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

    private void OnError(string error)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            var alert = new Alert
            {
                Timestamp = DateTime.Now,
                Level = ThreatLevel.Info,
                Category = "System",
                Title = "Система",
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
}