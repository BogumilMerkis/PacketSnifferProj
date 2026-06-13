using System.Net.Sockets;
using System.Text;

namespace PacketSniffer.Core.Notifications;

/// <summary>
/// Forwards alerts to a SIEM / syslog collector as RFC 5424 messages over UDP or TCP.
/// UDP is fire-and-forget; TCP uses octet-counting framing (RFC 6587) which collectors
/// such as rsyslog/syslog-ng accept reliably.
/// </summary>
public sealed class SyslogNotificationChannel : NotificationChannelBase
{
    private readonly SyslogOptions _opt;
    private readonly string _hostName = Ascii(Environment.MachineName);
    private readonly int _procId = Environment.ProcessId;

    public SyslogNotificationChannel(SyslogOptions opt) : base(opt) => _opt = opt;

    public override string Name => $"syslog({_opt.Protocol.ToString().ToLowerInvariant()}://{_opt.Host}:{_opt.Port})";

    public override async Task SendAsync(AlertNotification n, CancellationToken ct)
    {
        var message = SyslogFormatter.Format(n, _opt.Facility, _opt.AppName, _hostName, _procId);
        var bytes = Encoding.UTF8.GetBytes(message);

        if (_opt.Protocol == SyslogProtocol.Udp)
        {
            using var udp = new UdpClient();
            await udp.SendAsync(bytes, bytes.Length, _opt.Host, _opt.Port).WaitAsync(ct);
        }
        else
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(_opt.Host, _opt.Port, ct);
            await using var stream = tcp.GetStream();
            // RFC 6587 octet-counting: "<length> <message>".
            var framed = Encoding.UTF8.GetBytes($"{bytes.Length} ");
            await stream.WriteAsync(framed, ct);
            await stream.WriteAsync(bytes, ct);
            await stream.FlushAsync(ct);
        }
    }

    private static string Ascii(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s) sb.Append(c is > ' ' and < (char)127 ? c : '_');
        return sb.Length == 0 ? "-" : sb.ToString();
    }
}
