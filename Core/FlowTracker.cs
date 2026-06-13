using System.Collections.Concurrent;
using System.Net;
using PacketDotNet;

namespace PacketSniffer.Core;

/// <summary>
/// Stateful, connection-oriented analysis - the anomaly-detection half of the engine
/// (the signature half is <see cref="SignatureEngine"/>). Tracks bidirectional-ish flows
/// keyed by the 5-tuple and maintains per-source sliding windows for scan/sweep detection.
///
/// Thread-safe: multiple analysis workers may call <see cref="Process"/> concurrently.
/// Long-lived (registered as a singleton); <see cref="Reset"/> clears state between captures.
/// </summary>
public sealed class FlowTracker
{
    private readonly SnifferOptions _opt;

    private sealed class FlowState
    {
        public DateTime FirstSeen;
        public DateTime LastSeen;
        public long PacketCount;
        public long ByteCount;
        public int Syn, Fin, Rst;
        public double AvgEntropy; // cumulative moving average
    }

    // Per-source recon tracking: when each distinct dst port / dst host was last contacted.
    private sealed class ReconState
    {
        public readonly ConcurrentDictionary<int, DateTime> Ports = new();
        public readonly ConcurrentDictionary<IPAddress, DateTime> Hosts = new();
    }

    private readonly ConcurrentDictionary<FlowId, FlowState> _flows = new();
    private readonly ConcurrentDictionary<IPAddress, ReconState> _recon = new();

    private readonly record struct FlowId(IPAddress Src, IPAddress Dst, ushort SrcPort, ushort DstPort, ProtocolType Proto);

    public FlowTracker(SnifferOptions opt) => _opt = opt;

    public sealed record Result(FlowSnapshotDto? Snapshot, IReadOnlyList<RuleMatch> Matches, bool SnapshotChangedMeaningfully);

    public Result Process(Packet packet, DateTime nowUtc)
    {
        var l = PacketDecoder.Extract(packet);
        if (l.SrcIp == null || l.DstIp == null)
            return new Result(null, Array.Empty<RuleMatch>(), false);

        var id = new FlowId(l.SrcIp, l.DstIp, l.SrcPort, l.DstPort, l.Protocol);
        var flow = _flows.GetOrAdd(id, _ => new FlowState { FirstSeen = nowUtc, LastSeen = nowUtc });

        var matches = new List<RuleMatch>();
        FlowSnapshotDto snapshot;
        bool meaningful;

        lock (flow)
        {
            flow.LastSeen = nowUtc;
            flow.PacketCount++;
            flow.ByteCount += packet.TotalPacketLength;

            byte[] payload = packet.PayloadPacket?.PayloadData ?? packet.PayloadData ?? Array.Empty<byte>();
            if (payload.Length > 0)
            {
                double e = SignatureEngine.ShannonEntropy(payload);
                flow.AvgEntropy += (e - flow.AvgEntropy) / flow.PacketCount;
            }

            if (packet.Extract<TcpPacket>() is TcpPacket tcp && tcp.Flags != 0)
            {
                int f = tcp.Flags;
                if ((f & 0x02) != 0) flow.Syn++;
                if ((f & 0x01) != 0) flow.Fin++;
                if ((f & 0x04) != 0) flow.Rst++;
            }

            EvaluateFlow(id, flow, matches);
            snapshot = Snapshot(id, l, flow, nowUtc, matches);

            // Emit to UI on first sight, on a verdict change, or every 10th packet - never per-packet.
            meaningful = flow.PacketCount == 1 || matches.Count > 0 || flow.PacketCount % 10 == 0;
        }

        EvaluateRecon(l, nowUtc, matches);
        return new Result(snapshot, matches, meaningful);
    }

    private void EvaluateFlow(FlowId id, FlowState f, List<RuleMatch> matches)
    {
        bool isTcp = id.Proto == ProtocolType.Tcp;

        // SYN flood / half-open scan: many SYNs, no graceful teardown.
        if (isTcp && f.Syn > _opt.SynFloodThreshold && f.Fin == 0 && f.Rst == 0)
            matches.Add(Rules.SynFlood);

        // Sustained high packet rate from a single flow - DoS / flood indicator.
        double dur = (f.LastSeen - f.FirstSeen).TotalSeconds;
        if (dur > 1 && f.PacketCount / dur > _opt.HighRatePacketsPerSecond)
            matches.Add(Rules.HighRate);

        // Long-lived TCP connection that never closes - beaconing / tunnel indicator.
        if (isTcp && f.PacketCount > 1000 && f.Fin == 0)
            matches.Add(Rules.LongLived);

        // High average entropy on a cleartext service port - encrypted payload where none is expected.
        if (f.AvgEntropy > _opt.HighEntropyThreshold &&
            (IsPlaintextPort(id.SrcPort) || IsPlaintextPort(id.DstPort)))
            matches.Add(Rules.FlowEntropy);
    }

    private static bool IsPlaintextPort(ushort p) => p is 80 or 53 or 23 or 21 or 25;

    private void EvaluateRecon(PacketDecoder.L3L4 l, DateTime now, List<RuleMatch> matches)
    {
        if (l.SrcIp == null || l.DstPort == 0) return;
        var recon = _recon.GetOrAdd(l.SrcIp, _ => new ReconState());
        var window = now - TimeSpan.FromSeconds(_opt.ScanWindowSeconds);

        recon.Ports[l.DstPort] = now;
        if (l.DstIp != null) recon.Hosts[l.DstIp] = now;

        int distinctPorts = recon.Ports.Count(kv => kv.Value >= window);
        int distinctHosts = recon.Hosts.Count(kv => kv.Value >= window);

        // Vertical scan: one source hitting many ports on (typically) one host.
        if (distinctPorts >= _opt.PortScanDistinctPorts) matches.Add(Rules.PortScan);
        // Horizontal sweep: one source touching the same port across many hosts.
        if (distinctHosts >= _opt.HostSweepDistinctHosts) matches.Add(Rules.HostSweep);
    }

    private static FlowSnapshotDto Snapshot(FlowId id, PacketDecoder.L3L4 l, FlowState f, DateTime now, IReadOnlyList<RuleMatch> m)
    {
        var verdict = VerdictMapping.VerdictOf(m);
        return new FlowSnapshotDto(
            Key: $"{id.Src}:{id.SrcPort}-{id.Dst}:{id.DstPort}-{id.Proto}",
            Src: $"{id.Src}:{id.SrcPort}",
            Dest: $"{id.Dst}:{id.DstPort}",
            Protocol: id.Proto.ToString(),
            PacketCount: f.PacketCount,
            ByteCount: f.ByteCount,
            Syn: f.Syn, Fin: f.Fin, Rst: f.Rst,
            Duration: (f.LastSeen - f.FirstSeen).TotalSeconds,
            Verdict: verdict.ToString(),
            Entropy: Math.Round(f.AvgEntropy, 3),
            LastSeen: new DateTimeOffset(now, TimeSpan.Zero).ToUnixTimeSeconds());
    }

    /// <summary>Evicts idle flows and stale recon windows. Called periodically by the session janitor.</summary>
    public void Sweep(DateTime now)
    {
        var idle = TimeSpan.FromSeconds(_opt.FlowIdleTimeoutSeconds);
        foreach (var kv in _flows)
            if (now - kv.Value.LastSeen > idle) _flows.TryRemove(kv.Key, out _);

        var window = now - TimeSpan.FromSeconds(_opt.ScanWindowSeconds);
        foreach (var kv in _recon)
        {
            foreach (var p in kv.Value.Ports) if (p.Value < window) kv.Value.Ports.TryRemove(p.Key, out _);
            foreach (var h in kv.Value.Hosts) if (h.Value < window) kv.Value.Hosts.TryRemove(h.Key, out _);
            if (kv.Value.Ports.IsEmpty && kv.Value.Hosts.IsEmpty) _recon.TryRemove(kv.Key, out _);
        }
    }

    public void Reset()
    {
        _flows.Clear();
        _recon.Clear();
    }

    public int ActiveFlows => _flows.Count;

    private static class Rules
    {
        public static readonly RuleMatch SynFlood   = new("PS-5001", "TCP SYN Flood / Half-Open Scan", Severity.High, "DoS", "T1499.001");
        public static readonly RuleMatch HighRate    = new("PS-5002", "Sustained High Packet Rate", Severity.Medium, "DoS", "T1499");
        public static readonly RuleMatch LongLived    = new("PS-5003", "Long-Lived Unclosed Connection", Severity.Low, "C2", "T1071");
        public static readonly RuleMatch FlowEntropy = new("PS-5004", "High-Entropy Flow on Cleartext Port", Severity.Medium, "Exfiltration", "T1048");
        public static readonly RuleMatch PortScan    = new("PS-5005", "Vertical Port Scan", Severity.High, "Reconnaissance", "T1046");
        public static readonly RuleMatch HostSweep   = new("PS-5006", "Horizontal Host Sweep", Severity.High, "Reconnaissance", "T1046");
    }
}
