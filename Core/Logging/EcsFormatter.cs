using System.Text.Json;

namespace PacketSniffer.Core.Logging;

/// <summary>
/// Bespoke formatter that renders an <see cref="Alert"/> as a single-line
/// Elastic Common Schema (ECS) JSON document - the format Elasticsearch/Kibana and
/// OpenTelemetry pipelines ingest natively. One JSON object per line (NDJSON).
///
/// Field selection follows ECS for an IDS detection: <c>event.kind=alert</c>,
/// <c>event.category=[intrusion_detection, network]</c>, plus the <c>threat.*</c>,
/// <c>rule.*</c>, <c>source.*</c>/<c>destination.*</c>, <c>network.*</c> and
/// <c>observer.*</c> field sets. See https://www.elastic.co/docs/reference/ecs .
/// </summary>
public static class EcsFormatter
{
    public const string EcsVersion = "8.11.0";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    public static string Format(Alert alert, AlertContext ctx)
    {
        var severity = SeverityMap.Parse(alert.Severity);
        var mitre = MitreAttack.Lookup(alert.Technique);

        var doc = new Dictionary<string, object?>
        {
            ["@timestamp"] = ctx.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            ["message"] = alert.Message,
            ["ecs"] = new Dictionary<string, object?> { ["version"] = EcsVersion },
            ["event"] = new Dictionary<string, object?>
            {
                ["kind"] = "alert",
                ["category"] = new[] { "intrusion_detection", "network" },
                ["type"] = new[] { "info" },
                ["action"] = Slug(alert.Category),
                ["severity"] = SeverityMap.ToEcs(severity),
                ["dataset"] = "packetsniffer.alerts",
                ["module"] = "packetsniffer",
                ["id"] = alert.Id,
            },
            ["observer"] = new Dictionary<string, object?>
            {
                ["type"] = "ids",
                ["vendor"] = "PacketSniffer",
                ["product"] = "PacketSniffer",
                ["hostname"] = ctx.SensorHost,
            },
            ["rule"] = new Dictionary<string, object?>
            {
                ["id"] = alert.Sid,
                ["name"] = alert.Signature,
                ["category"] = alert.Category,
                ["ruleset"] = "PacketSniffer Signature Engine",
            },
        };

        // source / destination (only when an IP was extracted)
        if (alert.Src != null)
            doc["source"] = Endpoint(alert.Src, ctx.SrcPort);
        if (alert.Dest != null)
            doc["destination"] = Endpoint(alert.Dest, ctx.DstPort);

        var network = new Dictionary<string, object?>
        {
            ["transport"] = ctx.TransportName,
            ["bytes"] = ctx.PacketLength,
        };
        if (ctx.IanaNumber is int iana) network["iana_number"] = iana.ToString();
        doc["network"] = network;

        // threat.* MITRE ATT&CK enrichment
        if (mitre != null)
        {
            doc["threat"] = new Dictionary<string, object?>
            {
                ["framework"] = MitreAttack.Framework,
                ["technique"] = new Dictionary<string, object?>
                {
                    ["id"] = new[] { mitre.TechniqueId },
                    ["name"] = new[] { mitre.TechniqueName },
                    ["reference"] = new[] { MitreAttack.TechniqueUrl(mitre.TechniqueId) },
                },
                ["tactic"] = new Dictionary<string, object?>
                {
                    ["id"] = new[] { mitre.TacticId },
                    ["name"] = new[] { mitre.TacticName },
                    ["reference"] = new[] { MitreAttack.TacticUrl(mitre.TacticId) },
                },
            };
        }

        return JsonSerializer.Serialize(doc, JsonOpts);
    }

    private static Dictionary<string, object?> Endpoint(string ip, ushort port)
    {
        var ep = new Dictionary<string, object?> { ["ip"] = ip };
        if (port != 0) ep["port"] = port;
        return ep;
    }

    // ECS event.action is a lowercase, machine-friendly token.
    private static string Slug(string s) => s.ToLowerInvariant().Replace(' ', '_');
}
