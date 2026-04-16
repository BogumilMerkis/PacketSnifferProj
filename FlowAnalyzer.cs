using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

public class FlowResult
{
    public FlowVerdict Verdict { get; set; }
    public FlowSnapshot? Snapshot { get; set; }
}

public class FlowAnalyzer : IDisposable
{
    private readonly ConcurrentDictionary<FlowKey, FlowStats> _flows = new();
    private readonly ConcurrentDictionary<System.Net.IPAddress, ConcurrentDictionary<ushort, DateTime>> _ipTracker = new();
    
    private const int PortScanThreshold = 20; 
    private static readonly TimeSpan PortScanTimeWindow = TimeSpan.FromSeconds(10); 
    private static readonly TimeSpan FlowTimeout = TimeSpan.FromMinutes(2);
    private readonly CancellationTokenSource _cleanupCts = new();

    public FlowAnalyzer()
    {
        _ = Task.Run(CleanupLoopAsync, _cleanupCts.Token);
    }

    public FlowResult ProcessPacket(Packet packet)
    {
        var ip = packet.Extract<IPPacket>();
        if (ip == null)
            return new FlowResult { Verdict = FlowVerdict.Unknown };

        ushort srcPort = 0, dstPort = 0;
        ProtocolType proto = ProtocolType.IPv4;

        if (packet.Extract<TcpPacket>() is TcpPacket tcp)
        {
            srcPort = tcp.SourcePort;
            dstPort = tcp.DestinationPort;
            proto = ProtocolType.Tcp;
        }
        else if(packet.Extract<UdpPacket>() is UdpPacket udp)
        {
            srcPort = udp.SourcePort;
            dstPort = udp.DestinationPort;
            proto = ProtocolType.Udp;
        }

        var key = new FlowKey(ip.SourceAddress, ip.DestinationAddress, srcPort, dstPort, proto);
        var stats = _flows.GetOrAdd(key, _ => new FlowStats { FirstSeen = DateTime.Now });

        UpdateStats(stats, packet);
        
        bool isPortScan = TrackAndDetectPortScan(ip.SourceAddress, dstPort);
        
        // Pass 'key' so we can check ports against the entropy score
        var verdict = ClassifyFlow(key, stats);
        
        if (isPortScan && verdict < FlowVerdict.Malicious)
        {
            verdict = FlowVerdict.Malicious;
        }
        
        return new FlowResult 
        { 
            Verdict = verdict,
            Snapshot = CreateSnapshot(key, stats, verdict, packet)
        };
    }

    private bool TrackAndDetectPortScan(System.Net.IPAddress sourceIp, ushort destPort)
    {
        // Don't track port 0 (usually ICMP/IGMP or invalid)
        if (destPort == 0) return false;

        // Get or add the tracker for this IP
        var portTracker = _ipTracker.GetOrAdd(sourceIp, _ => new ConcurrentDictionary<ushort, DateTime>());

        // Update the last seen time for this destination port
        var now = DateTime.Now;
        portTracker[destPort] = now;

        // Check how many unique ports were hit within the alert time window
        var limitTime = now - PortScanTimeWindow;
        
        int recentPortsHit = portTracker.Count(kvp => kvp.Value >= limitTime);

        return recentPortsHit >= PortScanThreshold;
    }

    private static void UpdateStats(FlowStats stats, Packet packet)
    {
        lock (stats)
        {
            stats.LastSeen = DateTime.Now; 
            stats.PacketCount++;
            stats.ByteCount += packet.Bytes.Length;

            // --- CUMULATIVE MOVING AVERAGE FOR ENTROPY ---
            // Extract payload to measure entropy (or fall back to packet bytes if empty)
            byte[] payloadBytes = packet.PayloadPacket?.Bytes ?? packet.Bytes;
            double currentEntropy = Helpers.CalculateShannonEntropy(payloadBytes);
            
            // CMA Formula: NewAverage = OldAverage + (NewValue - OldAverage) / N
            stats.AverageEntropy = stats.AverageEntropy + (currentEntropy - stats.AverageEntropy) / stats.PacketCount;

            if (packet.Extract<TcpPacket>() is TcpPacket tcp && tcp.Flags != 0)
            {
                int flags = (int)tcp.Flags;
                if ((flags & 0x02) != 0) stats.SynCount++;
                if ((flags & 0x01) != 0) stats.FinCount++;
                if ((flags & 0x04) != 0) stats.RstCount++;
            }
        }
    }

    private FlowSnapshot CreateSnapshot(FlowKey k, FlowStats stats, FlowVerdict verdict, Packet latestPacket)
    {
        lock (stats)
        {
            return new FlowSnapshot
            {
                key = $"{k.Source}:{k.SourcePort}-{k.Destination}:{k.DestinationPort}-{k.Protocol}",
                src = $"{k.Source}:{k.SourcePort}",
                dest = $"{k.Destination}:{k.DestinationPort}",
                protocol = k.Protocol.ToString(),
                packetCount = stats.PacketCount,
                byteCount = stats.ByteCount,
                syn = stats.SynCount,
                fin = stats.FinCount,
                rst = stats.RstCount,
                duration = (stats.LastSeen - stats.FirstSeen).TotalSeconds,
                verdict = verdict.ToString(),
                lastSeen = new DateTimeOffset(stats.LastSeen).ToUnixTimeSeconds(),
                entropy = stats.AverageEntropy,
                raw = BitConverter.ToString(latestPacket.Bytes).Replace("-", " ")
            };
        }
    }

    private static FlowVerdict ClassifyFlow(FlowKey key, FlowStats stats)
    {
        int score = 0;

        // Many SYNs without FIN/RST -> Usually scans or floods (Only applies to TCP)
        if (key.Protocol == ProtocolType.Tcp && stats.SynCount > 10 && stats.FinCount == 0 && stats.RstCount == 0)
            score += 5;

        // High packet rate instance
        var duration = (stats.LastSeen - stats.FirstSeen).TotalSeconds;
        if (duration > 0 && stats.PacketCount / duration > 250) // Increased threshold to 250 to allow normal downloads
            score += 5;

        // Long-life connection with little closures (Only applies to TCP)
        if (key.Protocol == ProtocolType.Tcp && stats.PacketCount > 1000 && stats.FinCount == 0)
            score += 3;

        // --- ENTROPY ANOMALY DETECTION ---
        // If average entropy > 7.5, the flow is heavily compressed or encrypted.
        if (stats.AverageEntropy > 7.5)
        {
            // If encrypted traffic is on plaintext ports (HTTP, DNS, Telnet), flag it as highly suspicious
            if (key.SourcePort == 80 || key.DestinationPort == 80 ||
                key.SourcePort == 53 || key.DestinationPort == 53 ||
                key.SourcePort == 23 || key.DestinationPort == 23)
            {
                score += 5; 
            }
            // General high entropy on non-HTTPS ports raises minor suspicion 
            else if (key.SourcePort != 443 && key.DestinationPort != 443)
            {
                score += 2;
            }
        }

        return score switch
        {
            >= 8 => FlowVerdict.Malicious,
            >= 4 => FlowVerdict.Suspicious,
            _ => FlowVerdict.Normal
        };
    }

    private async Task CleanupLoopAsync()
    {
        while (!_cleanupCts.Token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), _cleanupCts.Token);
                var now = DateTime.Now;

                // 1. Cleanup old flows
                foreach (var flow in _flows)
                {
                    if (now - flow.Value.LastSeen > FlowTimeout)
                    {
                        _flows.TryRemove(flow.Key, out _);
                    }
                }

                // 2. Cleanup old port scan trackers to prevent memory leaks
                var portScanLimit = now - PortScanTimeWindow;
                foreach (var ipTrackerEntry in _ipTracker)
                {
                    var portDict = ipTrackerEntry.Value;
                    foreach (var portEntry in portDict)
                    {
                        if (portEntry.Value < portScanLimit)
                            portDict.TryRemove(portEntry.Key, out _);
                    }
                    if (portDict.IsEmpty)
                        _ipTracker.TryRemove(ipTrackerEntry.Key, out _);
                }
            }
            catch (TaskCanceledException) { break; }
        }
    }

    public void Dispose()
    {
        _cleanupCts.Cancel();
        _cleanupCts.Dispose();
    }
}