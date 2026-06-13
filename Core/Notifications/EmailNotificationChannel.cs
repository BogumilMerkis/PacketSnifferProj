using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace PacketSniffer.Core.Notifications;

/// <summary>
/// Sends alert emails over SMTP using MailKit (the library Microsoft recommends in place
/// of the obsolete System.Net.Mail.SmtpClient). Off by default; intended for High/Critical
/// alerts so it doesn't become an alert-fatigue firehose.
/// </summary>
public sealed class EmailNotificationChannel : NotificationChannelBase
{
    private readonly EmailOptions _opt;

    public EmailNotificationChannel(EmailOptions opt) : base(opt) => _opt = opt;

    public override string Name => $"email({_opt.Host}:{_opt.Port})";

    public override async Task SendAsync(AlertNotification n, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_opt.Host) || string.IsNullOrWhiteSpace(_opt.From) || string.IsNullOrWhiteSpace(_opt.To))
            throw new InvalidOperationException("Email channel enabled but Host/From/To are not fully configured.");

        var a = n.Alert;
        var msg = new MimeMessage();
        msg.From.Add(MailboxAddress.Parse(_opt.From));
        foreach (var to in _opt.To.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            msg.To.Add(MailboxAddress.Parse(to));
        msg.Subject = $"[PacketSniffer] {a.Severity}: {a.Sid} {a.Signature}";
        msg.Body = new TextPart("plain")
        {
            Text =
                $"{a.Message}\n\n" +
                $"Severity:  {a.Severity}\n" +
                $"Category:  {a.Category}\n" +
                $"Technique: {a.Technique ?? "-"}\n" +
                $"Source:    {a.Src ?? "-"}:{n.Context.SrcPort}\n" +
                $"Dest:      {a.Dest ?? "-"}:{n.Context.DstPort}\n" +
                $"Transport: {n.Context.TransportName}\n" +
                $"Sensor:    {n.Context.SensorHost}\n" +
                $"Time:      {a.Timestamp}\n"
        };

        using var smtp = new SmtpClient { Timeout = _opt.TimeoutSeconds * 1000 };
        var secure = _opt.UseStartTls ? SecureSocketOptions.StartTls : SecureSocketOptions.Auto;
        await smtp.ConnectAsync(_opt.Host, _opt.Port, secure, ct);
        if (!string.IsNullOrEmpty(_opt.Username))
            await smtp.AuthenticateAsync(_opt.Username, _opt.Password ?? string.Empty, ct);
        await smtp.SendAsync(msg, ct);
        await smtp.DisconnectAsync(true, ct);
    }
}
