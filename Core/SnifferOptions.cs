namespace PacketSniffer.Core;

/// <summary>
/// Tunable thresholds for the capture pipeline and detection engine.
/// Bound from the "Sniffer" configuration section; defaults apply otherwise.
/// </summary>
public sealed class SnifferOptions
{
    public static readonly SnifferOptions Default = new();

    // Pipeline sizing
    public int CaptureChannelCapacity { get; set; } = 65_536;
    public int RingBufferSize { get; set; } = 16_384;
    public int BroadcastIntervalMs { get; set; } = 250;
    public int MaxPacketsPerBatch { get; set; } = 400;
    public int MaxFlowsPerBatch { get; set; } = 200;
    public int MaxAlertsPerBatch { get; set; } = 100;

    // Flow tracking
    public int FlowIdleTimeoutSeconds { get; set; } = 120;
    public double HighRatePacketsPerSecond { get; set; } = 250;
    public int SynFloodThreshold { get; set; } = 10;

    // Scan detection (sliding window over connection initiations)
    public int PortScanDistinctPorts { get; set; } = 20;
    public int HostSweepDistinctHosts { get; set; } = 20;
    public int ScanWindowSeconds { get; set; } = 10;

    // Entropy analysis. Entropy estimates are statistically meaningless on
    // tiny samples, so payloads below the minimum lengths are never scored.
    public double HighEntropyThreshold { get; set; } = 7.5;
    public double DnsEntropyThreshold { get; set; } = 5.5;
    public int MinPayloadForEntropy { get; set; } = 64;
    public int MinDnsPayloadForEntropy { get; set; } = 32;

    // Alerting
    public int AlertSuppressionSeconds { get; set; } = 10;
    public int MaxStoredAlerts { get; set; } = 500;
}
