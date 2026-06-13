using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace PacketSniffer.Core.Notifications;

/// <summary>
/// Background worker that drains the <see cref="NotificationQueue"/> and fans each alert
/// out to every registered channel whose severity threshold it meets. A channel that
/// throws is logged and skipped - one failing channel never blocks the others or the loop.
/// </summary>
public sealed class NotificationDispatcher : BackgroundService
{
    private readonly NotificationQueue _queue;
    private readonly IReadOnlyList<INotificationChannel> _channels;
    private readonly ILogger<NotificationDispatcher> _log;

    public NotificationDispatcher(
        NotificationQueue queue,
        IEnumerable<INotificationChannel> channels,
        ILogger<NotificationDispatcher> log)
    {
        _queue = queue;
        _channels = channels.ToArray();
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_channels.Count == 0) return; // nothing registered; idle out

        _log.LogInformation("Notification dispatcher started with {Count} channel(s): {Names}",
            _channels.Count, string.Join(", ", _channels.Select(c => c.Name)));

        try
        {
            await foreach (var n in _queue.Reader.ReadAllAsync(stoppingToken))
            {
                foreach (var ch in _channels)
                {
                    if (!ch.Handles(n.Severity)) continue;
                    try
                    {
                        await ch.SendAsync(n, stoppingToken);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                    {
                        return;
                    }
                    catch (Exception ex)
                    {
                        _log.LogWarning(ex, "Notification channel {Channel} failed for alert {Sid}",
                            ch.Name, n.Alert.Sid);
                    }
                }
            }
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
    }
}
