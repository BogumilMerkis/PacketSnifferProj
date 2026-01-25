using System;
using System.Net;
using PacketDotNet;

public record FlowKey(
    IPAddress Source,
    IPAddress Destination,
    ushort SourcePort,
    ushort DestinationPort,
    ProtocolType Protocol);