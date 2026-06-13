namespace PacketSniffer.Core.Logging;

public enum SecurityLogFormat { Ecs, Cef }

/// <summary>
/// Configuration for the bespoke security-event audit log. Bound from the
/// "SecurityLog" configuration section.
/// </summary>
public sealed class SecurityLogOptions
{
    /// <summary>Master switch. When false, alerts are not written to the audit log.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Wire format for each line: ECS (Elastic Common Schema JSON) or CEF (ArcSight).</summary>
    public SecurityLogFormat Format { get; set; } = SecurityLogFormat.Ecs;

    /// <summary>Directory for the rolling audit-log files (created if missing). Gitignored.</summary>
    public string Directory { get; set; } = "Logs";

    /// <summary>Number of dated files to retain before the oldest are deleted.</summary>
    public int RetainedFileCountLimit { get; set; } = 31;

    /// <summary>Per-file size cap in megabytes; the file also rolls when this is hit.</summary>
    public int FileSizeLimitMb { get; set; } = 50;
}
