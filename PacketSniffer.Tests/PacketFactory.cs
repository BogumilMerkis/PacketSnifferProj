using System.Net;
using System.Net.NetworkInformation;
using PacketDotNet;

namespace PacketSniffer.Tests;

/// <summary>
/// Shared helpers for building in-memory PacketDotNet packets for the test suite.
/// Mirrors how packets are assembled by the live capture pipeline so the detection
/// engine sees structurally valid frames.
/// </summary>
internal static class PacketFactory
{
    public const string SrcMac = "001122334455";
    public const string DstMac = "66778899AABB";

    /// <summary>Builds an Ethernet/IPv4/TCP frame with the given addressing and flags.</summary>
    public static EthernetPacket BuildTcp(
        string srcIp, string dstIp, ushort srcPort, ushort dstPort,
        byte flags = 0x10, byte[]? payload = null)
    {
        var eth = new EthernetPacket(
            PhysicalAddress.Parse(SrcMac),
            PhysicalAddress.Parse(DstMac),
            EthernetType.IPv4);
        var ipv4 = new IPv4Packet(IPAddress.Parse(srcIp), IPAddress.Parse(dstIp));
        var tcp = new TcpPacket(srcPort, dstPort) { Flags = flags };

        if (payload is { Length: > 0 })
            tcp.PayloadData = payload;

        ipv4.PayloadPacket = tcp;
        eth.PayloadPacket = ipv4;
        eth.UpdateCalculatedValues();
        return eth;
    }

    /// <summary>Builds an Ethernet/IPv4/UDP frame.</summary>
    public static EthernetPacket BuildUdp(
        string srcIp, string dstIp, ushort srcPort, ushort dstPort, byte[]? payload = null)
    {
        var eth = new EthernetPacket(
            PhysicalAddress.Parse(SrcMac),
            PhysicalAddress.Parse(DstMac),
            EthernetType.IPv4);
        var ipv4 = new IPv4Packet(IPAddress.Parse(srcIp), IPAddress.Parse(dstIp));
        var udp = new UdpPacket(srcPort, dstPort);

        if (payload is { Length: > 0 })
            udp.PayloadData = payload;

        ipv4.PayloadPacket = udp;
        eth.PayloadPacket = ipv4;
        eth.UpdateCalculatedValues();
        return eth;
    }

    /// <summary>Deterministic high-entropy fill: 0,1,2,...,255 repeated. Approaches 8 bits/byte.</summary>
    public static byte[] HighEntropyBytes(int length)
    {
        var data = new byte[length];
        for (int i = 0; i < length; i++)
            data[i] = (byte)(i & 0xFF);
        return data;
    }
}
