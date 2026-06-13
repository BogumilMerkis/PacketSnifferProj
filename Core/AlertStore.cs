using System.Collections.Concurrent;

namespace PacketSniffer.Core;

/// <summary>
/// Bounded, time-suppressed alert log. Mirrors how a real IDS throttles repeat
/// signatures: the same (sid, src, dst) tuple won't re-alert within the suppression
/// window, so a scan or flood produces one alert rather than thousands.
/// </summary>
public sealed class AlertStore
{
    private readonly SnifferOptions _opt;
    private readonly ConcurrentQueue<Alert> _alerts = new();
    private readonly ConcurrentDictionary<string, DateTime> _lastSeen = new();
    private long _nextId;

    public AlertStore(SnifferOptions opt) => _opt = opt;

    /// <summary>Records an alert if it isn't currently suppressed. Returns the alert, or null if suppressed.</summary>
    public Alert? TryRecord(RuleMatch rule, DateTime nowUtc, string? src, string? dest, string? protocol)
    {
        var key = $"{rule.Sid}|{src}|{dest}";
        if (_lastSeen.TryGetValue(key, out var last) &&
            (nowUtc - last).TotalSeconds < _opt.AlertSuppressionSeconds)
        {
            _lastSeen[key] = nowUtc; // refresh so a continuous attack stays suppressed
            return null;
        }
        _lastSeen[key] = nowUtc;

        var alert = new Alert(
            Id: Interlocked.Increment(ref _nextId),
            Timestamp: nowUtc.ToLocalTime().ToString("o"),
            Sid: rule.Sid,
            Signature: rule.Name,
            Severity: rule.Severity.ToString(),
            Category: rule.Category,
            Technique: rule.Technique,
            Src: src, Dest: dest, Protocol: protocol,
            Message: $"[{rule.Sid}] {rule.Name} ({rule.Category}{(rule.Technique is null ? "" : $", {rule.Technique}")})");

        _alerts.Enqueue(alert);
        while (_alerts.Count > _opt.MaxStoredAlerts && _alerts.TryDequeue(out _)) { }
        return alert;
    }

    public IReadOnlyList<Alert> Recent(int max) => _alerts.Reverse().Take(max).ToArray();

    public void Reset()
    {
        while (_alerts.TryDequeue(out _)) { }
        _lastSeen.Clear();
        Interlocked.Exchange(ref _nextId, 0);
    }
}
