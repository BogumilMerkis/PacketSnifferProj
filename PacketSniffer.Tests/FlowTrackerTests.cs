using System;
using System.Linq;
using PacketSniffer.Core;
using Xunit;

namespace PacketSniffer.Tests;

public class FlowTrackerTests
{
    [Fact]
    public void Process_VerticalPortScan_ProducesPs5005()
    {
        var tracker = new FlowTracker(SnifferOptions.Default);
        var now = DateTime.UtcNow;
        bool sawScan = false;

        // 25 SYN packets from one source, each to a different destination port.
        for (ushort port = 1; port <= 25; port++)
        {
            var eth = PacketFactory.BuildTcp("10.0.0.99", "10.0.0.1", 40000, port, flags: 0x02);
            var result = tracker.Process(eth, now);
            if (result.Matches.Any(m => m.Sid == "PS-5005"))
                sawScan = true;
        }

        Assert.True(sawScan, "Expected a vertical port scan (PS-5005) after 25 distinct ports.");
    }

    [Fact]
    public void Process_SynFlood_ProducesPs5001()
    {
        var tracker = new FlowTracker(SnifferOptions.Default);
        var now = DateTime.UtcNow;
        bool sawFlood = false;

        // Many SYN-only packets on the SAME 5-tuple (threshold is 10).
        for (int i = 0; i < 15; i++)
        {
            var eth = PacketFactory.BuildTcp("10.0.0.50", "10.0.0.1", 40000, 80, flags: 0x02);
            var result = tracker.Process(eth, now);
            if (result.Matches.Any(m => m.Sid == "PS-5001"))
                sawFlood = true;
        }

        Assert.True(sawFlood, "Expected a SYN flood (PS-5001) after >10 SYNs on one flow.");
    }

    [Fact]
    public void Process_SingleBenignAck_NoMatchesAndMeaningfulSnapshot()
    {
        var tracker = new FlowTracker(SnifferOptions.Default);
        var eth = PacketFactory.BuildTcp("192.168.1.10", "8.8.8.8", 50000, 443, flags: 0x10);

        var result = tracker.Process(eth, DateTime.UtcNow);

        Assert.Empty(result.Matches);
        Assert.NotNull(result.Snapshot);
        Assert.True(result.SnapshotChangedMeaningfully, "First packet of a flow should be meaningful.");
    }

    [Fact]
    public void Reset_ClearsActiveFlows()
    {
        var tracker = new FlowTracker(SnifferOptions.Default);
        var eth = PacketFactory.BuildTcp("192.168.1.10", "8.8.8.8", 50000, 443, flags: 0x10);
        tracker.Process(eth, DateTime.UtcNow);

        Assert.True(tracker.ActiveFlows > 0);

        tracker.Reset();
        Assert.Equal(0, tracker.ActiveFlows);
    }
}
