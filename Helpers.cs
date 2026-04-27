using System;
using System.Net.Sockets;
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;


public static class Helpers
{
    public static string HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        var hash = KeyDerivation.Pbkdf2(
        password,
        salt,
        KeyDerivationPrf.HMACSHA256,
        iterationCount: 100_000,
        numBytesRequested: 32);


        return Convert.ToBase64String(salt) + ":" +
        Convert.ToBase64String(hash);
    }

    public enum PacketVerdict
	{
		Benign,
		Suspicious,
		Malicious,
		Unknown
	}

	public static PacketVerdict ClassifyPacket(Packet packet)
	{
		if (packet == null)
			return PacketVerdict.Unknown;

		int score = 0;

        var eth = packet.Extract<EthernetPacket>();
        var arp = packet.Extract<ArpPacket>();
        var ip = packet.Extract<IPPacket>();
		var tcp = packet.Extract<TcpPacket>();
		var udp = packet.Extract<UdpPacket>();

        if(eth != null)
        {
            // Source MAC should never be broadcast address (Deliberately malformed frame)
            if (eth.SourceHardwareAddress.ToString().Equals("FFFFFFFFFFFF", StringComparison.OrdinalIgnoreCase))
            {
                score += 10;
            }
        }

        if (arp != null)
        {
            // Gratuitous ARP Check (Sender IP == Target IP)
            // Widely used in ARP Poisoning to overwrite router ARP tables for MITM attacks.
            if (arp.SenderProtocolAddress != null && arp.TargetProtocolAddress != null)
            {
                if (arp.SenderProtocolAddress.Equals(arp.TargetProtocolAddress))
                {
                    score += 4;
                }
            }
        }

        if (arp != null && eth != null)
        {
            // The physical MAC address that sent the frame MUST match the MAC address 
            // inside the ARP protocol payload. If they differ, it is definitively a spoofed packet.
            if (!eth.SourceHardwareAddress.Equals(arp.SenderHardwareAddress))
            {
                score += 8; // High indicator of active ARP Spoofing / MITM
            }
        }

        if (ip != null)
        {
            var srcIpBytes = ip.SourceAddress.GetAddressBytes();

            // Check if Source IP is 255.255.255.255 (Broadcast)
            if (srcIpBytes[0] == 255 && srcIpBytes[1] == 255 && srcIpBytes[2] == 255 && srcIpBytes[3] == 255)
            {
                score += 5; // Impossible legitimate traffic
            }

            // Check if Source IP is in the Multicast Range (224.x.x.x - 239.x.x.x)
            if (srcIpBytes[0] >= 224 && srcIpBytes[0] <= 239)
            {
                score += 5; // Multicast addresses can only be Destinations, never Sources
            }
        }

        // Layer 3: Land Attack Check
        if (ip != null && ip.SourceAddress.Equals(ip.DestinationAddress))
        {
            score += 10; // A machine should never send a public network packet to itself over the wire
        }

        var icmp = packet.Extract<IcmpV4Packet>();
        if (icmp != null && icmp.PayloadData.Length > 64)
        {
            // A standard windows ping is only 32 bytes. Linux is 48. Anything over 64 
            // carrying real data is highly suspicious of Ping Tunneling data exfiltration.
            score += 6;
        }

        // Layer 4: Reflection Attack Port Loop
        if (tcp != null && tcp.SourcePort == tcp.DestinationPort)
        {
            score += 6;
        }
        if (udp != null && udp.SourcePort == udp.DestinationPort)
        {
            score += 6;
        }

        // Sanity checks
        if (ip != null && isMalformed(ip))
			score += 5;
        if (tcp != null && isMalformedTcp(tcp))
            score += 5;

		if (tcp != null && HasSuspiciousTcpFlags(tcp))
			score += 5;

        // Check for IP fragmentation (Evading firewall detection)
        if (packet.Extract<IPv4Packet>() is IPv4Packet ipv4)
        {
            if (ipv4.FragmentOffset > 0 || (int)ipv4.FragmentFlags != 0)
            {
                score += 3;  // High volume of fragmented packets is very suspicious
            }
        }

        // Payload Inspection
        if (tcp != null && tcp.PayloadData?.Length > 0)
		{
			if (ContainsExploitStrings(tcp.PayloadData))
				score += 7;
                
            // Check for encrypted/compressed data on Port 80
            if (tcp.SourcePort == 80 || tcp.DestinationPort == 80)
            {
                double entropy = CalculateShannonEntropy(tcp.PayloadData);
                if (entropy > 7.5) // Max entropy is 8.0, 7.5+ usually means encrypted
                {
                    // Encrypted traffic on a plaintext port is highly suspicious
                    score += 5; 
                }
            }
		}
		else if(udp != null && udp.PayloadData?.Length > 0)
		{
            if (ContainsExploitStrings(udp.PayloadData))
                score += 7;
                
            // Check for high entropy on DNS (Port 53) - possible DNS tunneling
            if (udp.SourcePort == 53 || udp.DestinationPort == 53)
            {
                double entropy = CalculateShannonEntropy(udp.PayloadData);
                if (entropy > 5.5) // DNS normally has lower entropy
                {
                    score += 4;
                }
            }
        }

		return score switch
		{
			>= 10 => PacketVerdict.Malicious,
			>= 4 => PacketVerdict.Suspicious,
			>= 0 => PacketVerdict.Benign,
			_ => PacketVerdict.Unknown
		};
    }

	public static bool isMalformed(IPPacket p)
	{
		try
		{
            if (p is IPPacket ip)
            {
                if (ip.TotalLength < ip.HeaderLength * 4)
                    return true;

                if (ip.TimeToLive <= 0)
                    return true;
            }

            if (p.PayloadPacket is TcpPacket tcp)
            {
                return tcp.DataOffset < 5;
            }
			return false;
        }
		catch
		{
			return true;
		}
	}

    public static bool isMalformedTcp(TcpPacket tcp)
    {
        try
        {
			return tcp.DataOffset < 5;
        }
        catch
        {
            return true;
        }
    }

    public static bool HasSuspiciousTcpFlags(TcpPacket tcp)
	{
		var flags = (int)tcp.Flags;
		
        const int FIN = 0x01;
        const int SYN = 0x02;
        const int RST = 0x04;
        const int PSH = 0x08;
        const int ACK = 0x10;
        const int URG = 0x20;

        if (flags == 0)
			return true;

		if ((flags & SYN) != 0 && (flags & FIN) != 0)
			return true;

		if ((flags & FIN) != 0 && (flags & PSH) != 0 && (flags & URG) != 0)
			return true;

		return false;
	}

    // Very basic, no encryption detection, just looking for common strings used in exploits.
    public static bool ContainsExploitStrings(byte[] payload)
	{
		if (payload == null || payload.Length == 0)
			return false;

		string data;

		try
		{
			data = Encoding.ASCII.GetString(payload);
		}
		catch
		{
			return false;
		}
		// Common exploit strings used to perform operations on a win/linx device.
        string[] signatures =
        {
            "cmd.exe",
            "/bin/sh",
            "/bin/bash",
            "../",
            "../../../",
            "powershell",
            "nc -e",
            "wget ",
            "curl "
        };

		return signatures.Any(sig => data.IndexOf(sig, StringComparison.OrdinalIgnoreCase) >= 0);
    }

	/// FORMATS TCP FLAGS TO READABLE.
	public static string FormatTcpFlags(TcpPacket tcp)
	{
		int flags = (int)tcp.Flags;

		var sb = new StringBuilder();

		if ((flags & 0x01) != 0) sb.Append("FIN ");
		if ((flags & 0x02) != 0) sb.Append("SYN ");
		if ((flags & 0x04) != 0) sb.Append("RST ");
		if ((flags & 0x08) != 0) sb.Append("PSH ");
		if ((flags & 0x10) != 0) sb.Append("ACK ");
		if ((flags & 0x20) != 0) sb.Append("URG ");

		return sb.Length == 0 ? "NONE" : sb.ToString().Trim();
	}

    // Calculates the Shannon entropy of the given byte array. Useful for detecting encrypted or compressed data.
    public static double CalculateShannonEntropy(byte[] data)
    {
        if (data == null || data.Length == 0) return 0.0;

        int[] frequencies = new int[256];
        foreach (byte b in data)
            frequencies[b]++;

        double entropy = 0.0;
        foreach (int freq in frequencies)
        {
            if (freq > 0)
            {
                double probability = (double)freq / data.Length;
                entropy -= probability * Math.Log(probability, 2);
            }
        }
        return entropy; // Value between 0 and 8. > 7.5 usually means encrypted/compressed.
    }
}
