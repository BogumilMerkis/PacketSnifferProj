using System;
using System.Collections.Generic;
using System.Text;
using PacketDotNet;

namespace PacketSniffer.Core;

/// <summary>
/// Stateless, per-packet IDS detection engine modelled on Suricata signatures.
/// Each heuristic is a named rule with a stable SID, severity, category and (where applicable)
/// a MITRE ATT&amp;CK technique id. Flow/state-based detection lives in the flow tracker, not here.
/// </summary>
public static class SignatureEngine
{
    // ---- Rule definitions (immutable catalog) -------------------------------------------------
    // Defining each RuleMatch once and reusing it avoids per-packet allocations and keeps SIDs stable.

    private static readonly RuleMatch BroadcastSrcMac =
        new("PS-1001", "Broadcast Source MAC", Severity.High, "Spoofing", "T1557");
    private static readonly RuleMatch GratuitousArp =
        new("PS-1002", "Gratuitous ARP", Severity.Medium, "Spoofing", "T1557.002");
    private static readonly RuleMatch ArpMacMismatch =
        new("PS-1003", "ARP MAC Mismatch", Severity.High, "Spoofing", "T1557.002");

    private static readonly RuleMatch BroadcastSrcIp =
        new("PS-2001", "Broadcast Source IP", Severity.Medium, "Anomaly", null);
    private static readonly RuleMatch MulticastSrcIp =
        new("PS-2002", "Multicast Source IP", Severity.Medium, "Anomaly", null);
    private static readonly RuleMatch LandAttack =
        new("PS-2003", "LAND Attack", Severity.High, "DoS", "T1499");
    private static readonly RuleMatch FragmentationEvasion =
        new("PS-2004", "IP Fragmentation Evasion", Severity.Low, "Evasion", "T1599");
    private static readonly RuleMatch MalformedIpHeader =
        new("PS-2005", "Malformed IP Header", Severity.Medium, "Anomaly", null);

    private static readonly RuleMatch IcmpTunnel =
        new("PS-3001", "ICMP Tunnel / Oversized Payload", Severity.Medium, "Exfiltration", "T1048.003");
    private static readonly RuleMatch TcpNullScan =
        new("PS-3002", "TCP Null Flags (Null Scan)", Severity.Medium, "Reconnaissance", "T1046");
    private static readonly RuleMatch TcpSynFin =
        new("PS-3003", "TCP SYN+FIN (Invalid Combo)", Severity.Medium, "Reconnaissance", "T1046");
    private static readonly RuleMatch TcpXmasScan =
        new("PS-3004", "TCP FIN+PSH+URG (Xmas Scan)", Severity.Medium, "Reconnaissance", "T1046");
    private static readonly RuleMatch MalformedTcpHeader =
        new("PS-3005", "Malformed TCP Header", Severity.Medium, "Anomaly", null);
    private static readonly RuleMatch TcpPortLoop =
        new("PS-3006", "Reflection Port Loop (TCP)", Severity.Medium, "DoS", "T1499");
    private static readonly RuleMatch UdpPortLoop =
        new("PS-3007", "Reflection Port Loop (UDP)", Severity.Medium, "DoS", "T1499");

    private static readonly RuleMatch ExploitPayload =
        new("PS-4001", "Exploit Signature in Payload", Severity.High, "Exploitation", "T1190");
    private static readonly RuleMatch HighEntropyPlaintext =
        new("PS-4002", "High-Entropy Payload on Plaintext Port (80)", Severity.Medium, "Exfiltration", "T1048");
    private static readonly RuleMatch DnsTunneling =
        new("PS-4003", "Possible DNS Tunneling", Severity.Medium, "Exfiltration", "T1048.003");

    // TCP flag bit masks (PacketDotNet exposes a combined Flags word).
    private const int FIN = 0x01;
    private const int SYN = 0x02;
    private const int RST = 0x04;
    private const int PSH = 0x08;
    private const int ACK = 0x10;
    private const int URG = 0x20;

    // Entropy gating thresholds. Short samples make entropy statistically meaningless,
    // so we refuse to score them (an intentional improvement over the original code).
    private const int Plaintext80MinLen = 64;
    private const int DnsTunnelMinLen = 32;

    /// <summary>
    /// Inspects a single packet against every stateless rule and returns all matches.
    /// An empty list means the packet looked clean. Never throws: a malformed packet that
    /// trips a parse exception is reported as a malformed-header anomaly rather than crashing.
    /// </summary>
    public static IReadOnlyList<RuleMatch> Inspect(Packet packet)
    {
        var matches = new List<RuleMatch>();
        if (packet == null) return matches;

        // Each layer is inspected inside its own guard so a parse fault in one layer
        // cannot suppress matches already found in another.
        TryInspectEthernetAndArp(packet, matches);
        TryInspectIp(packet, matches);
        TryInspectIcmp(packet, matches);
        TryInspectTcp(packet, matches);
        TryInspectUdp(packet, matches);

        return matches;
    }

    // ---- Layer 2: Ethernet / ARP --------------------------------------------------------------

    private static void TryInspectEthernetAndArp(Packet packet, List<RuleMatch> matches)
    {
        try
        {
            var eth = packet.Extract<EthernetPacket>();
            var arp = packet.Extract<ArpPacket>();

            // A frame's source MAC can never legitimately be the broadcast address - it's a forged frame.
            if (eth != null &&
                eth.SourceHardwareAddress != null &&
                eth.SourceHardwareAddress.ToString().Equals("FFFFFFFFFFFF", StringComparison.OrdinalIgnoreCase))
            {
                matches.Add(BroadcastSrcMac);
            }

            // Sender == target protocol address is a gratuitous ARP, the staple primitive of ARP-cache poisoning.
            if (arp != null &&
                arp.SenderProtocolAddress != null &&
                arp.TargetProtocolAddress != null &&
                arp.SenderProtocolAddress.Equals(arp.TargetProtocolAddress))
            {
                matches.Add(GratuitousArp);
            }

            // The L2 source MAC must match the MAC advertised inside the ARP payload; a mismatch is active spoofing.
            if (eth != null && arp != null &&
                eth.SourceHardwareAddress != null &&
                !eth.SourceHardwareAddress.Equals(arp.SenderHardwareAddress))
            {
                matches.Add(ArpMacMismatch);
            }
        }
        catch
        {
            // A frame too malformed to parse its L2/ARP layers is itself anomalous, but there is no
            // dedicated L2 anomaly SID - swallow and let the IP/TCP guards report header anomalies.
        }
    }

    // ---- Layer 3: IP ---------------------------------------------------------------------------

    private static void TryInspectIp(Packet packet, List<RuleMatch> matches)
    {
        try
        {
            var ip = packet.Extract<IPPacket>();
            if (ip == null) return;

            var src = ip.SourceAddress?.GetAddressBytes();
            if (src != null && src.Length == 4)
            {
                // 255.255.255.255 as a *source* is impossible in legitimate traffic.
                if (src[0] == 255 && src[1] == 255 && src[2] == 255 && src[3] == 255)
                    matches.Add(BroadcastSrcIp);

                // Multicast (224-239.x.x.x) addresses are valid destinations only, never sources.
                if (src[0] >= 224 && src[0] <= 239)
                    matches.Add(MulticastSrcIp);
            }

            // Source == destination is a LAND attack: it loops a host's stack against itself to exhaust it.
            if (ip.SourceAddress != null && ip.SourceAddress.Equals(ip.DestinationAddress))
                matches.Add(LandAttack);

            // TotalLength shorter than the header, or a dead TTL, indicates a hand-crafted/malformed header.
            if (ip.TotalLength < ip.HeaderLength * 4 || ip.TimeToLive <= 0)
                matches.Add(MalformedIpHeader);

            // Fragmentation is frequently abused to slip payloads past stateless firewalls/IDS.
            if (packet.Extract<IPv4Packet>() is IPv4Packet ipv4 &&
                (ipv4.FragmentOffset > 0 || (int)ipv4.FragmentFlags != 0))
            {
                matches.Add(FragmentationEvasion);
            }
        }
        catch
        {
            // If the IP header can't even be parsed, that itself is a malformed-header anomaly.
            AddDistinct(matches, MalformedIpHeader);
        }
    }

    // ---- Layer 3: ICMP -------------------------------------------------------------------------

    private static void TryInspectIcmp(Packet packet, List<RuleMatch> matches)
    {
        try
        {
            var icmp = packet.Extract<IcmpV4Packet>();
            // A normal ping is 32 (Windows) / 48 (Linux) bytes; >64 bytes of payload hints at ICMP tunnelling.
            if (icmp != null && icmp.PayloadData != null && icmp.PayloadData.Length > 64)
                matches.Add(IcmpTunnel);
        }
        catch
        {
            // Ignore unparsable ICMP; nothing actionable without a valid header.
        }
    }

    // ---- Layer 4: TCP --------------------------------------------------------------------------

    private static void TryInspectTcp(Packet packet, List<RuleMatch> matches)
    {
        try
        {
            var tcp = packet.Extract<TcpPacket>();
            if (tcp == null) return;

            int flags = (int)tcp.Flags;

            // No flags set at all is a Null scan probe used to map open ports stealthily.
            if (flags == 0)
                matches.Add(TcpNullScan);

            // SYN+FIN together is an illegal combination used to evade naive firewalls during scanning.
            if ((flags & SYN) != 0 && (flags & FIN) != 0)
                matches.Add(TcpSynFin);

            // FIN+PSH+URG is the classic "Xmas" scan fingerprint.
            if ((flags & FIN) != 0 && (flags & PSH) != 0 && (flags & URG) != 0)
                matches.Add(TcpXmasScan);

            // DataOffset below 5 (20 bytes) is structurally impossible for a real TCP header.
            if (tcp.DataOffset < 5)
                matches.Add(MalformedTcpHeader);

            // Identical source/destination ports loop traffic back, a signature of reflection/DoS crafting.
            if (tcp.SourcePort == tcp.DestinationPort)
                matches.Add(TcpPortLoop);

            // Payload inspection.
            var payload = tcp.PayloadData;
            if (payload != null && payload.Length > 0)
            {
                ReadOnlySpan<byte> span = payload;

                // Shell/exploit primitives in cleartext payload indicate command injection / RCE attempts.
                if (ContainsExploitStrings(span))
                    matches.Add(ExploitPayload);

                // High entropy on port 80 means encrypted/compressed data hiding on a plaintext channel.
                if ((tcp.SourcePort == 80 || tcp.DestinationPort == 80) &&
                    payload.Length >= Plaintext80MinLen &&
                    ShannonEntropy(span) > 7.5)
                {
                    matches.Add(HighEntropyPlaintext);
                }
            }
        }
        catch
        {
            // A TCP header too broken to inspect is reported as a malformed-header anomaly.
            AddDistinct(matches, MalformedTcpHeader);
        }
    }

    // ---- Layer 4: UDP --------------------------------------------------------------------------

    private static void TryInspectUdp(Packet packet, List<RuleMatch> matches)
    {
        try
        {
            var udp = packet.Extract<UdpPacket>();
            if (udp == null) return;

            // Identical source/destination ports loop traffic back, a signature of reflection/DoS crafting.
            if (udp.SourcePort == udp.DestinationPort)
                matches.Add(UdpPortLoop);

            var payload = udp.PayloadData;
            if (payload != null && payload.Length > 0)
            {
                ReadOnlySpan<byte> span = payload;

                // Shell/exploit primitives in cleartext payload indicate command injection / RCE attempts.
                if (ContainsExploitStrings(span))
                    matches.Add(ExploitPayload);

                // DNS normally has low entropy; elevated entropy on port 53 suggests data tunnelled over DNS.
                if ((udp.SourcePort == 53 || udp.DestinationPort == 53) &&
                    payload.Length >= DnsTunnelMinLen &&
                    ShannonEntropy(span) > 5.5)
                {
                    matches.Add(DnsTunneling);
                }
            }
        }
        catch
        {
            // Ignore unparsable UDP; there is no UDP-specific anomaly SID and nothing actionable remains.
        }
    }

    // ---- Shared utilities (consumed by flow tracker and unit tests - keep public & stable) -----

    /// <summary>
    /// Classic Shannon entropy over a 256-bucket frequency table. Result is 0..8 bits/byte.
    /// Returns 0.0 for empty input; returns 0.0 for uniform data and 2.0 for {1,2,3,4}.
    /// </summary>
    public static double ShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0.0;

        Span<int> frequencies = stackalloc int[256];
        foreach (byte b in data)
            frequencies[b]++;

        double entropy = 0.0;
        double length = data.Length;
        foreach (int freq in frequencies)
        {
            if (freq > 0)
            {
                double probability = freq / length;
                entropy -= probability * Math.Log(probability, 2);
            }
        }
        return entropy;
    }

    /// <summary>
    /// ASCII-decodes the payload and case-insensitively scans for common exploit/shell primitives.
    /// Returns false for empty payloads. Deliberately simple: it does not attempt to defeat encoding.
    /// </summary>
    public static bool ContainsExploitStrings(ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty) return false;

        string data;
        try
        {
            data = Encoding.ASCII.GetString(payload);
        }
        catch
        {
            return false;
        }

        // Common primitives used to execute commands or pull tooling onto a compromised host.
        foreach (var sig in ExploitSignatures)
        {
            if (data.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
        }
        return false;
    }

    private static readonly string[] ExploitSignatures =
    {
        "cmd.exe",
        "/bin/sh",
        "/bin/bash",
        "../",
        "../../../",
        "powershell",
        "nc -e",
        "wget ",
        "curl ",
    };

    /// <summary>
    /// Renders the TCP flag bits as a space-joined string ("FIN SYN RST PSH ACK URG"),
    /// or "NONE" when no flags are set.
    /// </summary>
    public static string FormatTcpFlags(TcpPacket tcp)
    {
        if (tcp == null) return "NONE";

        int flags = (int)tcp.Flags;
        var sb = new StringBuilder();

        if ((flags & FIN) != 0) sb.Append("FIN ");
        if ((flags & SYN) != 0) sb.Append("SYN ");
        if ((flags & RST) != 0) sb.Append("RST ");
        if ((flags & PSH) != 0) sb.Append("PSH ");
        if ((flags & ACK) != 0) sb.Append("ACK ");
        if ((flags & URG) != 0) sb.Append("URG ");

        return sb.Length == 0 ? "NONE" : sb.ToString().Trim();
    }

    // ---- Helpers -------------------------------------------------------------------------------

    /// <summary>Adds a rule only if it isn't already present (avoids duplicate anomaly hits from catch blocks).</summary>
    private static void AddDistinct(List<RuleMatch> matches, RuleMatch rule)
    {
        for (int i = 0; i < matches.Count; i++)
            if (matches[i].Sid == rule.Sid) return;
        matches.Add(rule);
    }
}
