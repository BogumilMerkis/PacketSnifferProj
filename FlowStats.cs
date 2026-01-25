using System;

public class FlowStats
{
    public DateTime FirstSeen { get; } = DateTime.UtcNow;
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;

    public long PacketCount { get; set; }
    public long ByteCount { get; set; }

    public int SynCount { get; set; }
    public int FinCount { get; set; }
    public int RstCount { get; set; }
}