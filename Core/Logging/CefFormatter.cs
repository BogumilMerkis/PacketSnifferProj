using System.Globalization;
using System.Text;

namespace PacketSniffer.Core.Logging;

/// <summary>
/// Bespoke formatter that renders an <see cref="Alert"/> as an ArcSight Common Event
/// Format (CEF) line, the de-facto SIEM ingestion format:
///
///   CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
///
/// The MITRE technique and category ride in custom string fields (cs1/cs2 with their
/// *Label keys), which is the idiomatic CEF way to carry vendor-specific attributes.
/// Escaping follows the ArcSight CEF spec: header fields escape <c>\</c> and <c>|</c>;
/// extension values escape <c>\</c>, <c>=</c> and newlines.
/// </summary>
public static class CefFormatter
{
    public const int CefVersion = 0;
    public const string DeviceVendor = "PacketSniffer";
    public const string DeviceProduct = "FYP-IDS";
    public const string DeviceVersion = "1.0";

    public static string Format(Alert alert, AlertContext ctx)
    {
        var severity = SeverityMap.Parse(alert.Severity);

        var header = new StringBuilder("CEF:").Append(CefVersion).Append('|')
            .Append(EscapeHeader(DeviceVendor)).Append('|')
            .Append(EscapeHeader(DeviceProduct)).Append('|')
            .Append(EscapeHeader(DeviceVersion)).Append('|')
            .Append(EscapeHeader(alert.Sid)).Append('|')
            .Append(EscapeHeader(alert.Signature)).Append('|')
            .Append(SeverityMap.ToCef(severity)).Append('|');

        var ext = new List<string>();
        void Add(string key, string? value)
        {
            if (!string.IsNullOrEmpty(value)) ext.Add($"{key}={EscapeExtension(value)}");
        }

        Add("rt", ctx.TimestampUtc.ToString("MMM dd yyyy HH:mm:ss", CultureInfo.InvariantCulture));
        Add("src", alert.Src);
        Add("dst", alert.Dest);
        if (ctx.SrcPort != 0) Add("spt", ctx.SrcPort.ToString());
        if (ctx.DstPort != 0) Add("dpt", ctx.DstPort.ToString());
        Add("proto", ctx.Transport.ToString().ToUpperInvariant());
        Add("act", "detected");
        Add("dvchost", ctx.SensorHost);
        if (alert.Technique != null)
        {
            Add("cs1Label", "MitreTechnique");
            Add("cs1", alert.Technique);
        }
        Add("cs2Label", "Category");
        Add("cs2", alert.Category);

        return header.Append(string.Join(' ', ext)).ToString();
    }

    private static string EscapeHeader(string s) =>
        s.Replace("\\", "\\\\").Replace("|", "\\|");

    private static string EscapeExtension(string s) =>
        s.Replace("\\", "\\\\").Replace("=", "\\=").Replace("\n", "\\n").Replace("\r", "\\r");
}
