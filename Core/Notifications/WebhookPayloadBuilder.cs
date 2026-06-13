using System.Text.Json;

namespace PacketSniffer.Core.Notifications;

/// <summary>
/// Builds the JSON body for an outbound webhook in the shape the target expects:
/// Slack (coloured attachment + blocks), Discord (coloured embed), or a generic
/// flat alert document. Kept separate from the HTTP transport so it is unit-testable.
/// </summary>
public static class WebhookPayloadBuilder
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    public static string Build(WebhookFlavor flavor, AlertNotification n) => flavor switch
    {
        WebhookFlavor.Slack => Slack(n),
        WebhookFlavor.Discord => Discord(n),
        _ => Generic(n),
    };

    private static string Slack(AlertNotification n)
    {
        var a = n.Alert;
        var header = $":rotating_light: *{a.Severity}* — {a.Sid} {a.Signature}";
        var detail =
            $"*Source:* `{a.Src ?? "-"}` → *Dest:* `{a.Dest ?? "-"}`\n" +
            $"*Category:* {a.Category}" + (a.Technique is null ? "" : $"  •  *MITRE:* {a.Technique}");

        var payload = new
        {
            text = $"{a.Severity}: {a.Sid} {a.Signature}",
            attachments = new[]
            {
                new
                {
                    color = SlackColor(n.Severity),
                    blocks = new object[]
                    {
                        new { type = "section", text = new { type = "mrkdwn", text = $"{header}\n{detail}" } },
                        new { type = "context", elements = new object[]
                            { new { type = "mrkdwn", text = $"PacketSniffer • {n.Context.SensorHost} • {a.Timestamp}" } } },
                    }
                }
            }
        };
        return JsonSerializer.Serialize(payload, Web);
    }

    private static string Discord(AlertNotification n)
    {
        var a = n.Alert;
        var fields = new List<object>
        {
            new { name = "Source", value = a.Src ?? "-", inline = true },
            new { name = "Dest", value = a.Dest ?? "-", inline = true },
            new { name = "Category", value = a.Category, inline = true },
        };
        if (a.Technique != null) fields.Add(new { name = "MITRE", value = a.Technique, inline = true });

        var payload = new
        {
            username = "PacketSniffer",
            embeds = new[]
            {
                new
                {
                    title = $"{a.Severity} — {a.Sid} {a.Signature}",
                    description = a.Message,
                    color = DiscordColor(n.Severity),
                    fields = fields.ToArray(),
                }
            }
        };
        return JsonSerializer.Serialize(payload, Web);
    }

    // Generic: the alert plus the parsed network context, camelCase.
    private static string Generic(AlertNotification n)
    {
        var a = n.Alert;
        var payload = new
        {
            sid = a.Sid,
            signature = a.Signature,
            severity = a.Severity,
            category = a.Category,
            technique = a.Technique,
            source = new { ip = a.Src, port = n.Context.SrcPort },
            destination = new { ip = a.Dest, port = n.Context.DstPort },
            transport = n.Context.TransportName,
            message = a.Message,
            sensor = n.Context.SensorHost,
            timestamp = a.Timestamp,
        };
        return JsonSerializer.Serialize(payload, Web);
    }

    // Slack attachment colours (hex). Red for malicious, amber for suspicious, green otherwise.
    private static string SlackColor(Severity s) => s switch
    {
        >= Severity.High => "#d9332b",
        >= Severity.Low => "#e8a000",
        _ => "#36a64f",
    };

    // Discord embed colours (decimal RGB).
    private static int DiscordColor(Severity s) => s switch
    {
        >= Severity.High => 0xD9332B,
        >= Severity.Low => 0xE8A000,
        _ => 0x36A64F,
    };
}
