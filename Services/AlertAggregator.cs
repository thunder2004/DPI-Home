using System.Collections.Concurrent;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Агрегатор алертов — группирует все события от одного IP в одну карточку
/// </summary>
public class AlertAggregator : IDisposable
{
    private readonly ConcurrentDictionary<string, AlertGroup> _groups = new();
    private readonly Timer _flushTimer;
    private readonly TimeSpan _groupWindow = TimeSpan.FromSeconds(30);
    private readonly object _flushLock = new();

    public event Action<AlertGroup>? OnAlertGroup;

    public AlertAggregator()
    {
        _flushTimer = new Timer(_ => FlushExpired(), null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
    }

    public void Add(Alert alert)
    {
        var key = BuildKey(alert);

        var group = _groups.GetOrAdd(key, _ => new AlertGroup
        {
            GroupKey = key,
            SrcIp = alert.SrcIp,
            FirstSeen = alert.Timestamp,
            LastSeen = alert.Timestamp,
            TotalCount = 0,
            MaxLevel = ThreatLevel.Info,
            Categories = new Dictionary<string, ThreatInfo>()
        });

        lock (group)
        {
            group.LastSeen = alert.Timestamp;
            group.TotalCount++;

            if (alert.Level > group.MaxLevel)
                group.MaxLevel = alert.Level;

            // Обновляем статистику по категории
            var catKey = string.IsNullOrEmpty(alert.ShortName) ? alert.Title : alert.ShortName;
            if (!group.Categories.ContainsKey(catKey))
            {
                group.Categories[catKey] = new ThreatInfo
                {
                    Icon = alert.LevelIcon,
                    Count = 0
                };
            }
            group.Categories[catKey].Count++;
            if (alert.LevelIcon != group.Categories[catKey].Icon)
                group.Categories[catKey].Icon = alert.LevelIcon;

            // Мержим порты (для Port Scan и других атак с целевыми портами)
            if (alert.ScannedPorts != null)
            {
                foreach (var port in alert.ScannedPorts)
                    group.Categories[catKey].Ports.Add(port);
            }
        }
    }

    public void FlushAll()
    {
        lock (_flushLock)
        {
            foreach (var key in _groups.Keys)
            {
                if (_groups.TryRemove(key, out var group))
                {
                    OnAlertGroup?.Invoke(group);
                }
            }
        }
    }

    private void FlushExpired()
    {
        var now = DateTime.Now;
        var cutoff = now - _groupWindow;

        lock (_flushLock)
        {
            foreach (var key in _groups.Keys)
            {
                if (_groups.TryGetValue(key, out var group))
                {
                    lock (group)
                    {
                        if (group.LastSeen < cutoff)
                        {
                            if (_groups.TryRemove(key, out var flushed))
                            {
                                OnAlertGroup?.Invoke(flushed);
                            }
                        }
                    }
                }
            }
        }
    }

    public void Clear()
    {
        lock (_flushLock)
        {
            _groups.Clear();
        }
    }

    private static string BuildKey(Alert alert)
    {
        // System-события держим в одной служебной карточке.
        if (alert.SrcIp == "system") return "system";
        // Разделяем по IP + категории: разные типы атак от одного IP не сливаются
        // в одну неинформативную карточку, но однотипный флуд остаётся сгруппирован.
        var cat = string.IsNullOrEmpty(alert.Category) ? "?" : alert.Category;
        return $"{alert.SrcIp}|{cat}";
    }

    public void Dispose()
    {
        _flushTimer?.Dispose();
        FlushAll();
    }
}