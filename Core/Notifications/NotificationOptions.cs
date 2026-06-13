namespace PacketSniffer.Core.Notifications;

/// <summary>Shared per-channel knobs: an on/off switch and a minimum severity to deliver.</summary>
public abstract class ChannelOptions
{
    public bool Enabled { get; set; } = false;
    /// <summary>Lowest severity that triggers delivery on this channel (Informational/Low/Medium/High/Critical).</summary>
    public string MinSeverity { get; set; } = "High";
}

public enum WebhookFlavor { Generic, Slack, Discord }

public sealed class WebhookOptions : ChannelOptions
{
    public string? Url { get; set; }
    public WebhookFlavor Flavor { get; set; } = WebhookFlavor.Slack;
    /// <summary>Optional shared secret. When set, the raw body is HMAC-SHA256 signed into the X-Signature header.</summary>
    public string? HmacSecret { get; set; }
    public int TimeoutSeconds { get; set; } = 10;
    public int MaxRetries { get; set; } = 3;
}

public enum SyslogProtocol { Udp, Tcp }

public sealed class SyslogOptions : ChannelOptions
{
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 514;
    public SyslogProtocol Protocol { get; set; } = SyslogProtocol.Udp;
    /// <summary>Syslog facility code; 16 = local0 (the conventional choice for app/security events).</summary>
    public int Facility { get; set; } = 16;
    public string AppName { get; set; } = "PacketSniffer";
}

public sealed class EmailOptions : ChannelOptions
{
    public string? Host { get; set; }
    public int Port { get; set; } = 587;
    public bool UseStartTls { get; set; } = true;
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? From { get; set; }
    /// <summary>Comma-separated recipient list.</summary>
    public string? To { get; set; }
    public int TimeoutSeconds { get; set; } = 20;
}

/// <summary>
/// Notification configuration, bound from the "Notifications" section. Each channel is
/// off by default; secrets (webhook URL/HMAC key, SMTP credentials) belong in
/// appsettings.Secrets.json or environment variables, never in source control.
/// </summary>
public sealed class NotificationOptions
{
    /// <summary>Bounded queue between the analysis thread and the dispatcher (drop-oldest under flood).</summary>
    public int QueueCapacity { get; set; } = 1000;

    public WebhookOptions Webhook { get; set; } = new();
    public SyslogOptions Syslog { get; set; } = new();
    public EmailOptions Email { get; set; } = new();
}
