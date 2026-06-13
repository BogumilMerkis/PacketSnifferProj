using System;
using PacketDotNet;
using PacketSniffer.Core;
using Xunit;

namespace PacketSniffer.Tests;

public class RingBufferTests
{
    private static PacketRecord MakeRecord(long id) => new()
    {
        Id = id,
        TimestampUtc = DateTime.UtcNow,
        LinkLayer = LinkLayers.Ethernet,
        Data = new byte[] { 1, 2, 3, 4 },
        Src = "1.1.1.1",
        Dest = "2.2.2.2",
        Protocol = "TCP",
        Verdict = Verdict.Benign,
    };

    [Fact]
    public void NextId_Increments()
    {
        var buffer = new PacketRingBuffer(new SnifferOptions());
        var first = buffer.NextId();
        var second = buffer.NextId();
        Assert.Equal(first + 1, second);
    }

    [Fact]
    public void Get_ReturnsRecordForKnownId_NullForMissing()
    {
        var buffer = new PacketRingBuffer(new SnifferOptions());
        var id = buffer.NextId();
        buffer.Add(MakeRecord(id));

        var found = buffer.Get(id);
        Assert.NotNull(found);
        Assert.Equal(id, found!.Id);

        Assert.Null(buffer.Get(999_999));
    }

    [Fact]
    public void Count_ReflectsAddedRecords()
    {
        var buffer = new PacketRingBuffer(new SnifferOptions());
        Assert.Equal(0, buffer.Count);

        buffer.Add(MakeRecord(buffer.NextId()));
        buffer.Add(MakeRecord(buffer.NextId()));
        Assert.Equal(2, buffer.Count);
    }

    [Fact]
    public void Add_BeyondCapacity_EvictsOldestAndCapsCount()
    {
        // Minimum capacity is 1024 regardless of the requested size; add a few past it.
        var buffer = new PacketRingBuffer(new SnifferOptions { RingBufferSize = 1 });

        long firstId = buffer.NextId();
        buffer.Add(MakeRecord(firstId));
        for (int i = 0; i < 1030; i++)
            buffer.Add(MakeRecord(buffer.NextId()));

        // Count never exceeds the 1024 floor capacity.
        Assert.True(buffer.Count <= 1024, $"Count {buffer.Count} should not exceed 1024 capacity.");
        // The very first record was evicted.
        Assert.Null(buffer.Get(firstId));
    }

    [Fact]
    public void Reset_ClearsBuffer()
    {
        var buffer = new PacketRingBuffer(new SnifferOptions());
        var id = buffer.NextId();
        buffer.Add(MakeRecord(id));
        Assert.Equal(1, buffer.Count);

        buffer.Reset();
        Assert.Equal(0, buffer.Count);
        Assert.Null(buffer.Get(id));
    }
}
