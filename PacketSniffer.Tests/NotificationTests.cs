using System;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using PacketDotNet;
using PacketSniffer.Core;
using PacketSniffer.Core.Notifications;
using Xunit;

namespace PacketSniffer.Tests;

public class NotificationTests
{
    private static Alert SampleAlert(string severity = "High") =>
        new(1, "2026-06-13T15:22:31+01:00", "PS-5005", "Vertical Port Scan", severity,
            "Reconnaissance", "T1046", "192.0.2.55", "10.0.0.10", "TCP 49321->445",
            "[PS-5005] Vertical Port Scan (Reconnaissance, T1046)");

    private static AlertNotification SampleNotification(string severity = "High") =>
        new(SampleAlert(severity),
            new AlertContext(49321, 445, ProtocolType.Tcp, 2520,
                new DateTime(2026, 6, 13, 14, 22, 31, DateTimeKind.Utc), "sensor-01"));

    // --- Webhook payloads ---------------------------------------------------

    [Fact]
    public void Slack_PayloadHasColouredAttachmentAndText()
    {
        var json = WebhookPayloadBuilder.Build(WebhookFlavor.Slack, SampleNotification());
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Contains("PS-5005", root.GetProperty("text").GetString());
        var attachment = root.GetProperty("attachments")[0];
        Assert.Equal("#d9332b", attachment.GetProperty("color").GetString()); // High -> red
        Assert.True(attachment.GetProperty("blocks").GetArrayLength() >= 1);
    }

    [Fact]
    public void Discord_PayloadHasEmbedWithNumericColour()
    {
        var json = WebhookPayloadBuilder.Build(WebhookFlavor.Discord, SampleNotification());
        using var doc = JsonDocument.Parse(json);
        var embed = doc.RootElement.GetProperty("embeds")[0];

        Assert.Equal(0xD9332B, embed.GetProperty("color").GetInt32());
        Assert.Contains("PS-5005", embed.GetProperty("title").GetString());
    }

    [Fact]
    public void Generic_PayloadCarriesFlatAlertFields()
    {
        var json = WebhookPayloadBuilder.Build(WebhookFlavor.Generic, SampleNotification());
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("PS-5005", root.GetProperty("sid").GetString());
        Assert.Equal("T1046", root.GetProperty("technique").GetString());
        Assert.Equal("192.0.2.55", root.GetProperty("source").GetProperty("ip").GetString());
        Assert.Equal(445, root.GetProperty("destination").GetProperty("port").GetInt32());
    }

    // --- HMAC signing -------------------------------------------------------

    [Fact]
    public void Sign_MatchesKnownHmacSha256Vector()
    {
        // RFC-style test vector: key="key", msg="The quick brown fox jumps over the lazy dog".
        var body = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
        var sig = WebhookNotificationChannel.Sign(body, "key");
        Assert.Equal("sha256=f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", sig);
    }

    [Fact]
    public void Sign_DiffersWithDifferentSecret()
    {
        var body = Encoding.UTF8.GetBytes("payload");
        Assert.NotEqual(
            WebhookNotificationChannel.Sign(body, "secret-a"),
            WebhookNotificationChannel.Sign(body, "secret-b"));
    }

    // --- Severity threshold routing ----------------------------------------

    [Fact]
    public void Channel_HandlesOnlyAtOrAboveMinSeverity()
    {
        var channel = new SyslogNotificationChannel(new SyslogOptions { MinSeverity = "High" });

        Assert.True(channel.Handles(Severity.High));
        Assert.True(channel.Handles(Severity.Critical));
        Assert.False(channel.Handles(Severity.Medium));
        Assert.False(channel.Handles(Severity.Low));
    }

    // --- Queue hand-off -----------------------------------------------------

    [Fact]
    public void Queue_EnqueuesAndDequeuesNotification()
    {
        var queue = new NotificationQueue(new NotificationOptions());
        var ctx = SampleNotification().Context;

        Assert.True(queue.Notify(SampleAlert(), ctx));
        Assert.True(queue.Reader.TryRead(out var n));
        Assert.Equal("PS-5005", n.Alert.Sid);
        Assert.Equal(Severity.High, n.Severity);
    }

    // --- Dispatcher end-to-end ---------------------------------------------

    [Fact]
    public async Task Dispatcher_DeliversQueuedAlertToHandlingChannel()
    {
        var queue = new NotificationQueue(new NotificationOptions());
        var recorder = new RecordingChannel(minSeverity: Severity.High);
        var dispatcher = new NotificationDispatcher(
            queue, new INotificationChannel[] { recorder }, NullLogger<NotificationDispatcher>.Instance);

        await dispatcher.StartAsync(CancellationToken.None);
        try
        {
            queue.Notify(SampleAlert("Low"), SampleNotification().Context);   // below threshold, skipped
            queue.Notify(SampleAlert("Critical"), SampleNotification().Context); // delivered

            var delivered = await recorder.FirstReceived.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal("PS-5005", delivered);
            Assert.DoesNotContain(recorder.Received, s => s == "low"); // the Low one never arrived
        }
        finally
        {
            await dispatcher.StopAsync(CancellationToken.None);
        }
    }

    private sealed class RecordingChannel : NotificationChannelBase
    {
        private readonly TaskCompletionSource<string> _first = new();
        public ConcurrentBag<string> Received { get; } = new();
        public Task<string> FirstReceived => _first.Task;

        public RecordingChannel(Severity minSeverity)
            : base(new SyslogOptions { MinSeverity = minSeverity.ToString() }) { }

        public override string Name => "recording";

        public override Task SendAsync(AlertNotification n, CancellationToken ct)
        {
            Received.Add(n.Alert.Sid);
            _first.TrySetResult(n.Alert.Sid);
            return Task.CompletedTask;
        }
    }
}
