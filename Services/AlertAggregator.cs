using System.Collections.Concurrent;
using DPI_Home.Models;

namespace DPI_Home.Services;

/// <summary>
/// Агрегатор алертов — группирует однотипные события по ключу
/// и отправляет их пачками, чтобы лог не был простынёй
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

    /// <summary>
    /// Добавить алерт в агрегатор. Если есть группа с таким же ключом — увеличиваем счётчик.
    /// Если группа "созрела" (прошло 30 сек с последнего обновления) — отправляем.
    /// </summary>
    public void Add(Alert alert)
    {
        var key = BuildKey(alert);

        var group = _groups.GetOrAdd(key, _ => new AlertGroup
        {
            GroupKey = key,
            Category = alert.Category,
            Title = alert.Title,
            Description = alert.Description,
            SrcIp = alert.SrcIp,
            DstIp = alert.DstIp,
            DstPort = alert.DstPort,
            Protocol = alert.Protocol,
            Level = alert.Level,
            FirstSeen = alert.Timestamp,
            LastSeen = alert.Timestamp,
            TotalCount = 0,
            MaxScore = 0
        });

        lock (group)
        {
            group.LastSeen = alert.Timestamp;
            group.TotalCount++;
            if (alert.Score > group.MaxScore) group.MaxScore = alert.Score;
            if (alert.Level > group.Level) group.Level = alert.Level;
        }
    }

    /// <summary>
    /// Отправить все накопившиеся группы немедленно (при очистке лога, остановке и т.д.)
    /// </summary>
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
        // Группируем по категории + IP источника + порту назначения
        return $"{alert.Category}|{alert.SrcIp}|{alert.DstPort}";
    }

    public void Dispose()
    {
        _flushTimer?.Dispose();
        FlushAll();
    }
}
