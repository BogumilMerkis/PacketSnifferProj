namespace PacketSniffer.Core.Notifications;

/// <summary>An alert plus its network context, queued for delivery.</summary>
public readonly record struct AlertNotification(Alert Alert, AlertContext Context)
{
    public Severity Severity => SeverityMap.Parse(Alert.Severity);
}

/// <summary>
/// A pluggable outbound notification channel (chat webhook, syslog/SIEM, email...).
/// Implementations are registered as singletons; the dispatcher fans every queued
/// alert out to each channel that <see cref="Handles"/> its severity.
/// </summary>
public interface INotificationChannel
{
    string Name { get; }

    /// <summary>True when this channel should deliver an alert of the given severity.</summary>
    bool Handles(Severity severity);

    Task SendAsync(AlertNotification notification, CancellationToken ct);
}

/// <summary>Base class wiring the shared severity-threshold behaviour from <see cref="ChannelOptions"/>.</summary>
public abstract class NotificationChannelBase : INotificationChannel
{
    private readonly Severity _minSeverity;

    protected NotificationChannelBase(ChannelOptions opt) =>
        _minSeverity = SeverityMap.Parse(opt.MinSeverity);

    public abstract string Name { get; }

    public bool Handles(Severity severity) => severity >= _minSeverity;

    public abstract Task SendAsync(AlertNotification notification, CancellationToken ct);
}
