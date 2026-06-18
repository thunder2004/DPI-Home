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
    private readonly DispatcherTimer _statsTimer;
    private readonly object _alertLock = new();
    private readonly object _httpsLock = new();

    private TrafficStats _stats = new();
    private bool _isConnected;
    private string _connectionStatus = "Ожидание подключения MikroTik...";
    private string _statusColor = "#FF9800";
    private int _listenPort = 2000;
    private long _packetCounter;
    private int _httpsConnectionCount;
    private int _httpsEstablishedCount;
    private int _httpsSynFloodCount;

    public ObservableCollection<Alert> Alerts { get; } = new();
    public ObservableCollection<Alert> RecentAlerts { get; } = new();
    public ObservableCollection<HttpsConnection> HttpsConnections { get; } = new();

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
            ConnectionStatus = value ? "✅ MikroTik подключён" : "⏳ Ожидание подключения MikroTik...";
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

    public int HttpsConnectionCount
    {
        get => _httpsConnectionCount;
        set { _httpsConnectionCount = value; OnPropertyChanged(); }
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

    public ICommand StartCommand { get; }
    public ICommand StopCommand { get; }

    public MainViewModel()
    {
        StartCommand = new AsyncRelayCommand(StartAsync);
        StopCommand = new RelayCommand(Stop);

        _sniffer = CreateSniffer();
        _analyzer = new TrafficAnalyzer();

        _analyzer.OnAlert += OnAlert;
        _analyzer.OnHttpsConnectionUpdate += OnHttpsConnectionUpdate;

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

    private void OnPacketReceived(RawPacket packet)
    {
        Interlocked.Increment(ref _packetCounter);
        _analyzer.Analyze(packet);
    }

    private void OnAlert(Alert alert)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            lock (_alertLock)
            {
                Alerts.Insert(0, alert);
                RecentAlerts.Insert(0, alert);

                if (Alerts.Count > 1000) Alerts.RemoveAt(Alerts.Count - 1);
                if (RecentAlerts.Count > 100) RecentAlerts.RemoveAt(RecentAlerts.Count - 1);
            }
        });
    }

    private void OnHttpsConnectionUpdate(HttpsConnection conn)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            lock (_httpsLock)
            {
                var existing = HttpsConnections.FirstOrDefault(c =>
                    c.SrcIp == conn.SrcIp && c.SrcPort == conn.SrcPort &&
                    c.DstIp == conn.DstIp && c.DstPort == conn.DstPort);

                if (existing != null)
                {
                    var idx = HttpsConnections.IndexOf(existing);
                    HttpsConnections[idx] = conn;
                }
                else
                {
                    HttpsConnections.Insert(0, conn);
                }

                while (HttpsConnections.Count > 500)
                    HttpsConnections.RemoveAt(HttpsConnections.Count - 1);
            }
        });
    }

    private void OnError(string error)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            OnAlert(new Alert
            {
                Timestamp = DateTime.Now,
                Level = ThreatLevel.High,
                Category = "System",
                Title = "Ошибка",
                Description = error,
                Score = 0
            });
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
            AlertsToday = Alerts.Count,
            AlertsCritical = Alerts.Count(a => a.Level == ThreatLevel.Critical),
            AlertsHigh = Alerts.Count(a => a.Level == ThreatLevel.High),
            AlertsMedium = Alerts.Count(a => a.Level == ThreatLevel.Medium),
        };

        HttpsConnectionCount = HttpsConnections.Count;
        HttpsEstablishedCount = HttpsConnections.Count(c => c.State == ConnectionState.Established);
        HttpsSynFloodCount = Alerts.Count(a => a.Category == "SYN Flood");
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
