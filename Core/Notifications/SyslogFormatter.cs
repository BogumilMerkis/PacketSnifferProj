using System.Text;

namespace PacketSniffer.Core.Notifications;

/// <summary>
/// Bespoke RFC 5424 syslog message builder for alerts:
///
///   &lt;PRI&gt;1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
///
/// where PRI = facility*8 + severity. The alert detail rides in a private
/// STRUCTURED-DATA element (SD-ID <c>psAlert@32473</c>); MSGID carries the rule SID.
/// See https://datatracker.ietf.org/doc/html/rfc5424 .
/// </summary>
public static class SyslogFormatter
{
    /// <summary>Private-enterprise SD-ID suffix (RFC 5424 §6.3.2 uses 32473 in its examples).</summary>
    public const int EnterpriseNumber = 32473;

    public static string Format(AlertNotification n, int facility, string appName, string hostName, int procId)
    {
        var alert = n.Alert;
        int pri = facility * 8 + SeverityMap.ToSyslog(n.Severity);
        var ts = n.Context.TimestampUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

        var host = Ascii(hostName, 255);
        var app = Ascii(appName, 48);
        var msgId = Ascii(alert.Sid, 32);

        var sd = new StringBuilder($"[psAlert@{EnterpriseNumber}");
        Param(sd, "sid", alert.Sid);
        Param(sd, "severity", alert.Severity);
        Param(sd, "category", alert.Category);
        if (alert.Technique != null) Param(sd, "technique", alert.Technique);
        if (alert.Src != null) Param(sd, "src", alert.Src);
        if (alert.Dest != null) Param(sd, "dst", alert.Dest);
        sd.Append(']');

        return $"<{pri}>1 {ts} {host} {app} {procId} {msgId} {sd} {alert.Message}";
    }

    private static void Param(StringBuilder sd, string name, string value) =>
        sd.Append(' ').Append(name).Append("=\"").Append(EscapeSd(value)).Append('"');

    // RFC 5424 §6.3.3: inside SD-PARAM values, escape ", \ and ].
    private static string EscapeSd(string s) =>
        s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("]", "\\]");

    // HOSTNAME/APP-NAME/MSGID are printable ASCII with no spaces; fall back to NILVALUE.
    private static string Ascii(string? s, int max)
    {
        if (string.IsNullOrWhiteSpace(s)) return "-";
        var sb = new StringBuilder(Math.Min(s.Length, max));
        foreach (var c in s)
        {
            if (sb.Length >= max) break;
            sb.Append(c is > ' ' and < (char)127 ? c : '_');
        }
        return sb.Length == 0 ? "-" : sb.ToString();
    }
}
