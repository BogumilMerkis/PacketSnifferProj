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

public static class Helpers
{
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

		var ip = packet.Extract<IPPacket>();
		var tcp = packet.Extract<TcpPacket>();
		var udp = packet.Extract<UdpPacket>();

		// Sanity checks
		if (ip != null && isMalformed(ip))
			score += 5;
        if (tcp != null && isMalformedTcp(tcp))
            score += 5;

		if (tcp != null && HasSuspiciousTcpFlags(tcp))
			score += 3;

		// Payload Inspection
		if(tcp != null && tcp.PayloadData?.Length > 0)
		{
			if (ContainsExploitStrings(tcp.PayloadData))
				score += 7;
		}
		else if(udp != null && udp.PayloadData?.Length > 0)
		{
            if (ContainsExploitStrings(udp.PayloadData))
                score += 7;
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
}
