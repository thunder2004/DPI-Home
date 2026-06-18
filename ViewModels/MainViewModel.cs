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

    private TrafficStats _stats = new();
    private bool _isConnected;
    private string _connectionStatus = "Отключено";
    private string _statusColor = "#F44336";
    private string _hostAddress = "192.168.105.1";
    private int _hostPort = 2000;
    private long _packetCounter;

    public ObservableCollection<Alert> Alerts { get; } = new();
    public ObservableCollection<Alert> RecentAlerts { get; } = new();

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
            ConnectionStatus = value ? "Подключено" : "Отключено";
            StatusColor = value ? "#4CAF50" : "#F44336";
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

    public string HostAddress
    {
        get => _hostAddress;
        set { _hostAddress = value; OnPropertyChanged(); }
    }

    public int HostPort
    {
        get => _hostPort;
        set { _hostPort = value; OnPropertyChanged(); }
    }

    public ICommand ConnectCommand { get; }

    public MainViewModel()
    {
        ConnectCommand = new AsyncRelayCommand(ConnectAsync);
        _sniffer = CreateSniffer();
        _analyzer = new TrafficAnalyzer();

        _analyzer.OnAlert += OnAlert;

        _statsTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _statsTimer.Tick += UpdateStats;
        _statsTimer.Start();
    }

    private MikroTikSnifferService CreateSniffer()
    {
        var s = new MikroTikSnifferService(_hostAddress, _hostPort);
        s.OnPacketReceived += OnPacketReceived;
        s.OnError += OnError;
        s.OnConnectionChanged += OnConnectionChanged;
        return s;
    }

    public async Task ConnectAsync()
    {
        if (IsConnected)
        {
            _sniffer.Stop();
            IsConnected = false;
            return;
        }

        _sniffer = CreateSniffer();
        await _sniffer.StartAsync();
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

    private void OnError(string error)
    {
        Application.Current.Dispatcher.Invoke(() =>
        {
            OnAlert(new Alert
            {
                Timestamp = DateTime.Now,
                Level = ThreatLevel.High,
                Category = "System",
                Title = "Ошибка захвата",
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
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
