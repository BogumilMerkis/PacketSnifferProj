using PacketDotNet;

namespace PacketSniffer.Core;

/// <summary>
/// Extra network context captured at detection time and carried alongside an
/// <see cref="Alert"/> into the security log and notification channels. The
/// <see cref="Alert"/> record itself only keeps display strings; this struct
/// preserves the parsed ports/transport/length needed for ECS, CEF and syslog.
/// </summary>
public readonly record struct AlertContext(
    ushort SrcPort,
    ushort DstPort,
    ProtocolType Transport,
    int PacketLength,
    DateTime TimestampUtc,
    string SensorHost)
{
    /// <summary>Lowercase transport name for ECS (<c>network.transport</c>) - "tcp", "udp", "icmp"...</summary>
    public string TransportName => Transport switch
    {
        ProtocolType.Tcp => "tcp",
        ProtocolType.Udp => "udp",
        ProtocolType.Icmp => "icmp",
        ProtocolType.IcmpV6 => "ipv6-icmp",
        _ => Transport.ToString().ToLowerInvariant()
    };

    /// <summary>IANA protocol number for ECS (<c>network.iana_number</c>) and CEF, when known.</summary>
    public int? IanaNumber => Transport switch
    {
        ProtocolType.Tcp => 6,
        ProtocolType.Udp => 17,
        ProtocolType.Icmp => 1,
        ProtocolType.IcmpV6 => 58,
        _ => null
    };
}
