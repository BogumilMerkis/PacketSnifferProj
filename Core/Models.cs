using PacketDotNet;
using SharpPcap;

namespace PacketSniffer.Core;

public enum Verdict { Benign, Suspicious, Malicious }

public enum Severity { Informational, Low, Medium, High, Critical }

/// <summary>A detection rule hit. Sid/category/severity follow the Suricata signature model.</summary>
public sealed record RuleMatch(string Sid, string Name, Severity Severity, string Category, string? Technique);

/// <summary>A raw frame handed from the capture thread to the analysis pipeline.
/// Persist is false for offline pcap replay (already on disk).</summary>
public readonly record struct RawFrame(RawCapture Capture, bool Persist);

/// <summary>Lightweight row pushed to the UI. Full detail is fetched on demand by Id.</summary>
public sealed record PacketSummary(
    long Id, string Timestamp, string? Src, string? Dest,
    string? Protocol, int Length, string Verdict, bool Flagged);

/// <summary>Full packet retained in the ring buffer. Decode and hex dump are produced on demand.</summary>
public sealed class PacketRecord
{
    public required long Id { get; init; }
    public required DateTime TimestampUtc { get; init; }
    public required LinkLayers LinkLayer { get; init; }
    public required byte[] Data { get; init; }
    public string? Src { get; init; }
    public string? Dest { get; init; }
    public string? Protocol { get; init; }
    public Verdict Verdict { get; init; }
    public IReadOnlyList<RuleMatch> Matches { get; init; } = Array.Empty<RuleMatch>();
    public string? FlowKey { get; init; }
}

/// <summary>Alert event, shaped after Suricata's EVE alert records.</summary>
public sealed record Alert(
    long Id, string Timestamp, string Sid, string Signature, string Severity,
    string Category, string? Technique, string? Src, string? Dest, string? Protocol, string Message);

/// <summary>Point-in-time view of a tracked flow, sent to the UI.</summary>
public sealed record FlowSnapshotDto(
    string Key, string Src, string Dest, string Protocol,
    long PacketCount, long ByteCount, int Syn, int Fin, int Rst,
    double Duration, string Verdict, double Entropy, long LastSeen);

public static class VerdictMapping
{
    public static Verdict ToVerdict(this Severity s) => s switch
    {
        >= Severity.High => Verdict.Malicious,
        >= Severity.Low => Verdict.Suspicious,
        _ => Verdict.Benign
    };

    public static Severity MaxSeverity(IReadOnlyList<RuleMatch>? matches)
    {
        var max = Severity.Informational;
        if (matches == null) return max;
        foreach (var m in matches)
            if (m.Severity > max) max = m.Severity;
        return max;
    }

    public static Verdict VerdictOf(IReadOnlyList<RuleMatch>? matches) =>
        matches == null || matches.Count == 0 ? Verdict.Benign : MaxSeverity(matches).ToVerdict();
}
