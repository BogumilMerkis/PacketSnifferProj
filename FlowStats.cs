using System;

public class FlowStats
{
    public DateTime FirstSeen { get; set; } = DateTime.Now;
    public DateTime LastSeen { get; set; } = DateTime.Now;

    public long PacketCount { get; set; }
    public long ByteCount { get; set; }

    public int SynCount { get; set; }
    public int FinCount { get; set; }
    public int RstCount { get; set; }
    public double AverageEntropy { get; set; }
}