using System;
using System.Linq;
using PacketSniffer.Core;
using Xunit;

namespace PacketSniffer.Tests;

public class AlertStoreTests
{
    private static readonly RuleMatch SampleRule =
        new("PS-9999", "Test Rule", Severity.High, "TestCategory", "T0000");

    [Fact]
    public void TryRecord_SameTupleWithinWindow_SuppressesSecond()
    {
        var store = new AlertStore(new SnifferOptions());
        var now = DateTime.UtcNow;

        var first = store.TryRecord(SampleRule, now, "1.1.1.1", "2.2.2.2", "TCP");
        var second = store.TryRecord(SampleRule, now, "1.1.1.1", "2.2.2.2", "TCP");

        Assert.NotNull(first);
        Assert.Null(second);
    }

    [Fact]
    public void TryRecord_DifferentTuple_NotSuppressed()
    {
        var store = new AlertStore(new SnifferOptions());
        var now = DateTime.UtcNow;

        var first = store.TryRecord(SampleRule, now, "1.1.1.1", "2.2.2.2", "TCP");
        var second = store.TryRecord(SampleRule, now, "1.1.1.1", "3.3.3.3", "TCP");

        Assert.NotNull(first);
        Assert.NotNull(second);
    }

    [Fact]
    public void Recent_ReturnsMostRecentFirst()
    {
        var store = new AlertStore(new SnifferOptions());
        var now = DateTime.UtcNow;

        var a = store.TryRecord(SampleRule, now, "1.1.1.1", "2.2.2.2", "TCP");
        var b = store.TryRecord(SampleRule, now, "1.1.1.1", "3.3.3.3", "TCP");
        Assert.NotNull(a);
        Assert.NotNull(b);

        var recent = store.Recent(10);

        Assert.Equal(2, recent.Count);
        Assert.Equal(b!.Id, recent[0].Id); // most recent first
        Assert.Equal(a!.Id, recent[1].Id);
    }
}
