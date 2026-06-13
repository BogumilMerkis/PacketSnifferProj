using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using PacketDotNet;
using PacketSniffer.Core;
using PacketSniffer.Core.Logging;
using Xunit;

namespace PacketSniffer.Tests;

/// <summary>
/// End-to-end check of the bespoke audit log: an alert handed to
/// <see cref="SecurityEventLog"/> is written to a rolling file on disk in the
/// configured format (exercises the formatter + Serilog file sink together).
/// </summary>
public class SecurityEventLogTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ps-seclog-" + Guid.NewGuid().ToString("N"));

    private static Alert SampleAlert() =>
        new(1, "2026-06-13T15:22:31+01:00", "PS-5005", "Vertical Port Scan", "High",
            "Reconnaissance", "T1046", "192.0.2.55", "10.0.0.10", "TCP 49321->445",
            "[PS-5005] Vertical Port Scan (Reconnaissance, T1046)");

    private static AlertContext Ctx() =>
        new(49321, 445, ProtocolType.Tcp, 2520, new DateTime(2026, 6, 13, 14, 22, 31, DateTimeKind.Utc), "sensor-01");

    [Fact]
    public void Record_WritesEcsLineToRollingFile()
    {
        var opt = new SecurityLogOptions { Directory = _dir, Format = SecurityLogFormat.Ecs };
        using (var log = new SecurityEventLog(opt))
            log.Record(SampleAlert(), Ctx());
        // Dispose flushes and releases the file handle.

        var file = Directory.GetFiles(_dir, "security-*.ndjson").Single();
        var line = File.ReadAllLines(file).Single(l => l.Length > 0);

        using var doc = JsonDocument.Parse(line);
        Assert.Equal("PS-5005", doc.RootElement.GetProperty("rule").GetProperty("id").GetString());
        Assert.Equal("alert", doc.RootElement.GetProperty("event").GetProperty("kind").GetString());
    }

    [Fact]
    public void Record_WritesCefLineWhenConfigured()
    {
        var opt = new SecurityLogOptions { Directory = _dir, Format = SecurityLogFormat.Cef };
        using (var log = new SecurityEventLog(opt))
            log.Record(SampleAlert(), Ctx());

        var file = Directory.GetFiles(_dir, "security-*.cef").Single();
        var line = File.ReadAllLines(file).Single(l => l.Length > 0);
        Assert.StartsWith("CEF:0|PacketSniffer|FYP-IDS|", line);
    }

    [Fact]
    public void Record_DisabledLogWritesNothing()
    {
        var opt = new SecurityLogOptions { Directory = _dir, Enabled = false };
        using (var log = new SecurityEventLog(opt))
            log.Record(SampleAlert(), Ctx());

        Assert.False(Directory.Exists(_dir) && Directory.GetFiles(_dir).Length > 0);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); } catch { }
    }
}
