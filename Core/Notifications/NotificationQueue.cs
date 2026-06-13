using System.Threading.Channels;

namespace PacketSniffer.Core.Notifications;

/// <summary>
/// Non-blocking hand-off between the analysis thread and the notification dispatcher.
/// <see cref="Notify"/> only enqueues (a single non-blocking write); the bounded channel
/// drops the oldest pending notification under a flood so the capture pipeline is never
/// stalled on slow network I/O - the same back-pressure model the capture channel uses.
/// </summary>
public sealed class NotificationQueue
{
    private readonly Channel<AlertNotification> _channel;

    public NotificationQueue(NotificationOptions opt)
    {
        _channel = Channel.CreateBounded<AlertNotification>(
            new BoundedChannelOptions(opt.QueueCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false,
            });
    }

    public ChannelReader<AlertNotification> Reader => _channel.Reader;

    /// <summary>Fire-and-forget enqueue. Returns false if the item was dropped (queue full).</summary>
    public bool Notify(Alert alert, AlertContext context) =>
        _channel.Writer.TryWrite(new AlertNotification(alert, context));
}
