namespace PacketSniffer.Core;

/// <summary>
/// Maps the engine's 5-level <see cref="Severity"/> onto the numeric scales used by
/// the standard log/notification formats, so a single alert can be expressed
/// consistently across ECS, CEF and RFC 5424 syslog.
/// </summary>
public static class SeverityMap
{
    /// <summary>Parse the string severity stored on an <see cref="Alert"/> back to the enum.</summary>
    public static Severity Parse(string? severity) =>
        Enum.TryParse<Severity>(severity, ignoreCase: true, out var s) ? s : Severity.Informational;

    /// <summary>RFC 5424 syslog severity (0 Emergency .. 7 Debug). Lower = more urgent.</summary>
    public static int ToSyslog(Severity s) => s switch
    {
        Severity.Critical => 2, // Critical
        Severity.High     => 3, // Error
        Severity.Medium   => 4, // Warning
        Severity.Low      => 5, // Notice
        _                 => 6, // Informational
    };

    /// <summary>ArcSight CEF severity (0..10, 10 = most important). Maps onto Low/Medium/High/Very-High bands.</summary>
    public static int ToCef(Severity s) => s switch
    {
        Severity.Critical => 9, // Very-High (9-10)
        Severity.High     => 7, // High (7-8)
        Severity.Medium   => 5, // Medium (4-6)
        Severity.Low      => 3, // Low (0-3)
        _                 => 1,
    };

    /// <summary>Normalised numeric severity (0..100) for ECS <c>event.severity</c>.</summary>
    public static int ToEcs(Severity s) => s switch
    {
        Severity.Critical => 90,
        Severity.High     => 70,
        Severity.Medium   => 50,
        Severity.Low      => 30,
        _                 => 10,
    };
}
