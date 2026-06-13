using System.Security.Cryptography;
using System.Text;

namespace PacketSniffer.Core.Notifications;

/// <summary>
/// Posts alerts to an HTTP(S) webhook (Slack / Discord / generic). When an HMAC secret
/// is configured the raw body is signed with HMAC-SHA256 into the <c>X-Signature</c>
/// header (<c>sha256=&lt;hex&gt;</c>), the convention receivers use to authenticate the
/// payload. Transient failures are retried with exponential backoff.
/// </summary>
public sealed class WebhookNotificationChannel : NotificationChannelBase
{
    private readonly WebhookOptions _opt;
    private readonly IHttpClientFactory _httpFactory;

    public WebhookNotificationChannel(WebhookOptions opt, IHttpClientFactory httpFactory) : base(opt)
    {
        _opt = opt;
        _httpFactory = httpFactory;
    }

    public override string Name => $"webhook({_opt.Flavor.ToString().ToLowerInvariant()})";

    public override async Task SendAsync(AlertNotification n, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_opt.Url))
            throw new InvalidOperationException("Webhook channel enabled but no Url configured.");

        var body = WebhookPayloadBuilder.Build(_opt.Flavor, n);
        var bodyBytes = Encoding.UTF8.GetBytes(body);

        var client = _httpFactory.CreateClient("notifications");
        client.Timeout = TimeSpan.FromSeconds(_opt.TimeoutSeconds);

        for (int attempt = 0; ; attempt++)
        {
            try
            {
                using var content = new ByteArrayContent(bodyBytes);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

                using var req = new HttpRequestMessage(HttpMethod.Post, _opt.Url) { Content = content };
                req.Headers.TryAddWithoutValidation("X-Alert-Sid", n.Alert.Sid); // idempotency hint
                if (!string.IsNullOrEmpty(_opt.HmacSecret))
                    req.Headers.TryAddWithoutValidation("X-Signature", Sign(bodyBytes, _opt.HmacSecret));

                using var resp = await client.SendAsync(req, ct);
                if (resp.IsSuccessStatusCode) return;

                // 4xx (other than 429) won't succeed on retry - fail fast.
                if ((int)resp.StatusCode is >= 400 and < 500 && (int)resp.StatusCode != 429)
                    throw new HttpRequestException($"Webhook rejected with {(int)resp.StatusCode} {resp.StatusCode}.");

                if (attempt >= _opt.MaxRetries)
                    throw new HttpRequestException($"Webhook failed after {attempt + 1} attempts ({(int)resp.StatusCode}).");
            }
            catch (Exception) when (attempt < _opt.MaxRetries && !ct.IsCancellationRequested)
            {
                // Exponential backoff: 200ms, 400ms, 800ms, ...
                await Task.Delay(TimeSpan.FromMilliseconds(200 * Math.Pow(2, attempt)), ct);
                continue;
            }
            return;
        }
    }

    /// <summary>HMAC-SHA256 of the raw body, formatted "sha256=&lt;lowercase-hex&gt;".</summary>
    public static string Sign(byte[] body, string secret)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return "sha256=" + Convert.ToHexString(hmac.ComputeHash(body)).ToLowerInvariant();
    }
}
