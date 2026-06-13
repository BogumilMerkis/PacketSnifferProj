using System.Net;
using PacketDotNet;
using SharpPcap;

namespace PacketSniffer.Core;

/// <summary>
/// Pure decoding helpers. Kept separate from capture so the capture thread never
/// pays decode cost - decoding happens on the analysis worker, and the expensive
/// human-readable dump is produced only on demand when a UI client opens a packet.
/// </summary>
public static class PacketDecoder
{
    public readonly record struct L3L4 (
        IPAddress? SrcIp, IPAddress? DstIp, ushort SrcPort, ushort DstPort,
        ProtocolType Protocol, string Display);

    /// <summary>Cheap extraction of the addressing/protocol fields needed for summaries and flow keys.</summary>
    public static L3L4 Extract(Packet packet)
    {
        var ip = packet.Extract<IPPacket>();
        if (ip == null)
        {
            // Non-IP (ARP, LLDP, raw L2). Label by the highest decoded layer.
            var inner = packet.PayloadPacket?.GetType().Name.Replace("Packet", "");
            return new L3L4(null, null, 0, 0, ProtocolType.IPv4, inner ?? packet.GetType().Name.Replace("Packet", ""));
        }

        ushort sp = 0, dp = 0;
        var proto = ip.Protocol;
        string display = ip.Protocol.ToString();

        if (packet.Extract<TcpPacket>() is TcpPacket tcp)
        {
            sp = tcp.SourcePort; dp = tcp.DestinationPort; proto = ProtocolType.Tcp;
            display = $"TCP {sp}->{dp}";
        }
        else if (packet.Extract<UdpPacket>() is UdpPacket udp)
        {
            sp = udp.SourcePort; dp = udp.DestinationPort; proto = ProtocolType.Udp;
            display = $"UDP {sp}->{dp}";
        }
        else if (packet.Extract<IcmpV4Packet>() != null) display = "ICMP";
        else if (packet.Extract<IcmpV6Packet>() != null) display = "ICMPv6";

        return new L3L4(ip.SourceAddress, ip.DestinationAddress, sp, dp, proto, display);
    }

    public static Packet? TryParse(LinkLayers link, byte[] data)
    {
        try { return Packet.ParsePacket(link, data); }
        catch { return null; }
    }

    /// <summary>Wireshark-style hex+ASCII dump. Only called on demand for a single inspected packet.</summary>
    public static string HexDump(ReadOnlySpan<byte> data)
    {
        var sb = new System.Text.StringBuilder(data.Length * 4);
        for (int offset = 0; offset < data.Length; offset += 16)
        {
            sb.Append(offset.ToString("x4")).Append("  ");
            int end = Math.Min(offset + 16, data.Length);
            for (int i = offset; i < offset + 16; i++)
            {
                sb.Append(i < end ? data[i].ToString("x2") : "  ").Append(' ');
                if (i == offset + 7) sb.Append(' ');
            }
            sb.Append(' ');
            for (int i = offset; i < end; i++)
            {
                byte b = data[i];
                sb.Append(b >= 0x20 && b < 0x7f ? (char)b : '.');
            }
            sb.Append('\n');
        }
        return sb.ToString();
    }
}
