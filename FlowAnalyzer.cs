using System;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

public class FlowAnalyzer
{
    private FlowKey? _lastUpdatedKey;
    private readonly ConcurrentDictionary<FlowKey, FlowStats> _flows = new();

    private static readonly TimeSpan FlowTimeout = TimeSpan.FromMinutes(2);

    public FlowVerdict ProcessPacket(Packet packet)
    {
        var ip = packet.Extract<IPPacket>();
        if (ip == null)
            return FlowVerdict.Unknown;

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
        _lastUpdatedKey = key;

        var stats = _flows.GetOrAdd(key, _ => new FlowStats());

        UpdateStats(stats, packet);

        CleanupExpiredFlows();

        return ClassifyFlow(stats);
    }

    private static void UpdateStats(FlowStats stats, Packet packet)
    {
        stats.LastSeen = DateTime.Now;
        stats.PacketCount++;
        stats.ByteCount += packet.Bytes.Length;
        
        if (packet.Extract<TcpPacket>() is TcpPacket tcp)
        {
            if (tcp.Flags != 0)
            {
                int flags = (int)tcp.Flags;

                if ((flags & 0x02) != 0) stats.SynCount++;
                if ((flags & 0x01) != 0) stats.FinCount++;
                if ((flags & 0x04) != 0) stats.RstCount++;
            }
        }
    }

    private static FlowVerdict ClassifyFlow(FlowStats stats)
    {
        int score = 0;

        // Many SYNs without FIN/RST -> Usually scans or floods
        if (stats.SynCount > 10 && stats.FinCount == 0 && stats.RstCount == 0)
            score += 5;

        // High packet rate instance
        var duration = (stats.LastSeen - stats.FirstSeen).TotalSeconds;
        if (duration > 0 && stats.PacketCount / duration > 100)
            score += 5;

        // Long-life connection with little closures
        if (stats.PacketCount > 1000 && stats.FinCount == 0)
            score += 3;

        return score switch
        {
            >= 8 => FlowVerdict.Malicious,
            >= 4 => FlowVerdict.Suspicious,
            _ => FlowVerdict.Normal
        };
    }

    public FlowSnapshot? GetLastFlowSnapshot(Packet packet)
    {
        if (_lastUpdatedKey == null)
            return null;

        if (!_flows.TryGetValue(_lastUpdatedKey, out var stats))
            return null;

        var k = _lastUpdatedKey;

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
            verdict = ClassifyFlow(stats).ToString(),
            lastSeen = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        };
    }

    private void CleanupExpiredFlows()
    {
        var now = DateTime.UtcNow;

        foreach (var flow in _flows)
        {
            if (now - flow.Value.LastSeen > FlowTimeout)
            {
                _flows.TryRemove(flow.Key, out _);
            }
        }
    }
}