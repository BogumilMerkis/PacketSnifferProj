using PacketSniffer.Core;
using Xunit;

namespace PacketSniffer.Tests;

public class DecoderTests
{
    [Fact]
    public void Extract_TcpIpPacket_ReturnsAddressingAndPorts()
    {
        var eth = PacketFactory.BuildTcp("192.168.1.10", "8.8.8.8", 50000, 80, flags: 0x10);

        var l = PacketDecoder.Extract(eth);

        Assert.NotNull(l.SrcIp);
        Assert.NotNull(l.DstIp);
        Assert.Equal("192.168.1.10", l.SrcIp!.ToString());
        Assert.Equal("8.8.8.8", l.DstIp!.ToString());
        Assert.Equal(50000, l.SrcPort);
        Assert.Equal(80, l.DstPort);
        Assert.StartsWith("TCP", l.Display);
    }

    [Fact]
    public void HexDump_ContainsHexOfFirstByte()
    {
        byte[] data = { 0xDE, 0xAD, 0xBE, 0xEF };
        var dump = PacketDecoder.HexDump(data);

        // First byte rendered as "de" in the hex column.
        Assert.Contains("de", dump);
        Assert.Contains("ad", dump);
    }
}
