using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace PacketSniffer.Core.Logging;

/// <summary>
/// Bespoke security-event audit log. Every recorded <see cref="Alert"/> is written as
/// one structured line (ECS JSON or CEF) to a daily-rolling file under the configured
/// directory, separate from the application log. Serilog provides the rolling/retention
/// machinery; the per-line format is produced by <see cref="EcsFormatter"/> /
/// <see cref="CefFormatter"/>.
///
/// Alert volume is naturally low because <see cref="AlertStore"/> suppresses repeats by
/// (sid, src, dst), so the synchronous file write on the analysis thread is not a hot path.
/// </summary>
public sealed class SecurityEventLog : IDisposable
{
    private readonly SecurityLogOptions _opt;
    private readonly Logger? _logger;

    public SecurityEventLog(SecurityLogOptions opt)
    {
        _opt = opt;
        if (!opt.Enabled) return;

        System.IO.Directory.CreateDirectory(opt.Directory);
        // Single-segment extension: Serilog inserts the rolling date before the last
        // dot, so "security-.ndjson" becomes "security-20260613.ndjson".
        var extension = opt.Format == SecurityLogFormat.Cef ? "cef" : "ndjson";
        var path = Path.Combine(opt.Directory, $"security-.{extension}");

        _logger = new LoggerConfiguration()
            .MinimumLevel.Verbose()
            .WriteTo.File(
                path: path,
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: opt.RetainedFileCountLimit,
                fileSizeLimitBytes: (long)opt.FileSizeLimitMb * 1024 * 1024,
                rollOnFileSizeLimit: true,
                // Emit only the pre-rendered line; no Serilog decoration around it.
                outputTemplate: "{Message:l}{NewLine}")
            .CreateLogger();
    }

    /// <summary>Append one alert to the audit log. No-op when logging is disabled.</summary>
    public void Record(Alert alert, AlertContext ctx)
    {
        if (_logger == null) return;

        var line = _opt.Format == SecurityLogFormat.Cef
            ? CefFormatter.Format(alert, ctx)
            : EcsFormatter.Format(alert, ctx);

        // The rendered line rides as a property value, so its braces are never parsed
        // as message-template tokens.
        var severity = MapLevel(SeverityMap.Parse(alert.Severity));
        _logger.Write(severity, "{Line}", line);
    }

    private static LogEventLevel MapLevel(Severity s) => s switch
    {
        Severity.Critical => LogEventLevel.Fatal,
        Severity.High => LogEventLevel.Error,
        Severity.Medium => LogEventLevel.Warning,
        Severity.Low => LogEventLevel.Information,
        _ => LogEventLevel.Verbose,
    };

    public void Dispose() => _logger?.Dispose();
}
