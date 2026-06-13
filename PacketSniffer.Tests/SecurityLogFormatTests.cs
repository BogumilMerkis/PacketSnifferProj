using System;
using System.Text.Json;
using PacketDotNet;
using PacketSniffer.Core;
using PacketSniffer.Core.Logging;
using PacketSniffer.Core.Notifications;
using Xunit;

namespace PacketSniffer.Tests;

/// <summary>
/// Verifies the bespoke standards-aligned formatters (ECS, CEF, RFC 5424 syslog)
/// produce well-formed output with the correct fields, severity mapping and escaping.
/// </summary>
public class SecurityLogFormatTests
{
    private static readonly DateTime Ts = new(2026, 6, 13, 14, 22, 31, DateTimeKind.Utc);

    private static Alert SampleAlert(string severity = "High", string? technique = "T1046",
        string category = "Reconnaissance", string signature = "Vertical Port Scan") =>
        new(1, "2026-06-13T15:22:31.0010000+01:00", "PS-5005", signature, severity,
            category, technique, "192.0.2.55", "10.0.0.10", "TCP 49321->445",
            $"[PS-5005] {signature} ({category}, {technique})");

    private static AlertContext SampleCtx() =>
        new(49321, 445, ProtocolType.Tcp, 2520, Ts, "sensor-01");

    // --- ECS ----------------------------------------------------------------

    [Fact]
    public void Ecs_ProducesValidIdsAlertDocument()
    {
        var json = EcsFormatter.Format(SampleAlert(), SampleCtx());
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.EndsWith("Z", root.GetProperty("@timestamp").GetString());
        Assert.Equal("alert", root.GetProperty("event").GetProperty("kind").GetString());

        var categories = root.GetProperty("event").GetProperty("category");
        Assert.Contains("intrusion_detection", EnumerateStrings(categories));
        Assert.Contains("network", EnumerateStrings(categories));

        Assert.Equal(70, root.GetProperty("event").GetProperty("severity").GetInt32());
        Assert.Equal("ids", root.GetProperty("observer").GetProperty("type").GetString());

        Assert.Equal("192.0.2.55", root.GetProperty("source").GetProperty("ip").GetString());
        Assert.Equal(49321, root.GetProperty("source").GetProperty("port").GetInt32());
        Assert.Equal("10.0.0.10", root.GetProperty("destination").GetProperty("ip").GetString());

        Assert.Equal("tcp", root.GetProperty("network").GetProperty("transport").GetString());
        Assert.Equal("6", root.GetProperty("network").GetProperty("iana_number").GetString());

        Assert.Equal("PS-5005", root.GetProperty("rule").GetProperty("id").GetString());
    }

    [Fact]
    public void Ecs_EnrichesMitreTechniqueAndTactic()
    {
        var json = EcsFormatter.Format(SampleAlert(technique: "T1046"), SampleCtx());
        using var doc = JsonDocument.Parse(json);
        var threat = doc.RootElement.GetProperty("threat");

        Assert.Equal("MITRE ATT&CK", threat.GetProperty("framework").GetString());
        Assert.Equal("T1046", threat.GetProperty("technique").GetProperty("id")[0].GetString());
        Assert.Equal("TA0007", threat.GetProperty("tactic").GetProperty("id")[0].GetString());
        Assert.Equal("Discovery", threat.GetProperty("tactic").GetProperty("name")[0].GetString());
    }

    [Fact]
    public void Ecs_OmitsThreatBlockForUnknownTechnique()
    {
        var json = EcsFormatter.Format(SampleAlert(technique: null), SampleCtx());
        using var doc = JsonDocument.Parse(json);
        Assert.False(doc.RootElement.TryGetProperty("threat", out _));
    }

    // --- CEF ----------------------------------------------------------------

    [Fact]
    public void Cef_BuildsHeaderAndExtensionWithMitreInCustomField()
    {
        var line = CefFormatter.Format(SampleAlert(), SampleCtx());

        Assert.StartsWith("CEF:0|PacketSniffer|FYP-IDS|1.0|PS-5005|Vertical Port Scan|7|", line);
        Assert.Contains("src=192.0.2.55", line);
        Assert.Contains("dst=10.0.0.10", line);
        Assert.Contains("spt=49321", line);
        Assert.Contains("dpt=445", line);
        Assert.Contains("proto=TCP", line);
        Assert.Contains("cs1Label=MitreTechnique", line);
        Assert.Contains("cs1=T1046", line);
        Assert.Contains("cs2=Reconnaissance", line);
    }

    [Fact]
    public void Cef_EscapesPipeInHeaderField()
    {
        var line = CefFormatter.Format(SampleAlert(signature: "Scan|Probe"), SampleCtx());
        Assert.Contains("|Scan\\|Probe|", line);
    }

    // --- RFC 5424 syslog ----------------------------------------------------

    [Fact]
    public void Syslog_ComputesPriVersionAndStructuredData()
    {
        // facility 16 (local0) * 8 + severity 3 (High -> Error) = 131
        var line = SyslogFormatter.Format(
            new AlertNotification(SampleAlert(), SampleCtx()), 16, "PacketSniffer", "sensor-01", 4321);

        Assert.StartsWith("<131>1 ", line);
        Assert.Contains(" sensor-01 PacketSniffer 4321 PS-5005 ", line);
        Assert.Contains("[psAlert@32473 ", line);
        Assert.Contains("sid=\"PS-5005\"", line);
        Assert.Contains("technique=\"T1046\"", line);
        Assert.Contains("src=\"192.0.2.55\"", line);
    }

    [Fact]
    public void Syslog_EscapesClosingBracketInStructuredData()
    {
        var line = SyslogFormatter.Format(
            new AlertNotification(SampleAlert(category: "Odd]Category"), SampleCtx()),
            16, "PacketSniffer", "sensor-01", 1);
        Assert.Contains("category=\"Odd\\]Category\"", line);
    }

    [Fact]
    public void Syslog_CriticalMapsToSeverityTwo()
    {
        var line = SyslogFormatter.Format(
            new AlertNotification(SampleAlert(severity: "Critical"), SampleCtx()), 16, "App", "host", 1);
        // 16*8 + 2 = 130
        Assert.StartsWith("<130>1 ", line);
    }

    private static System.Collections.Generic.IEnumerable<string?> EnumerateStrings(JsonElement arr)
    {
        foreach (var e in arr.EnumerateArray()) yield return e.GetString();
    }
}
