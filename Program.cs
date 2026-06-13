using System.Net.WebSockets;
using PacketSniffer.Core;
using PacketSniffer.Core.Logging;
using PacketSniffer.Core.Notifications;
using Serilog;
using SharpPcap;

// Bootstrap logger: captures failures during host construction, before the full
// configuration is read. Replaced below by the configured logger.
Log.Logger = new LoggerConfiguration().WriteTo.Console().CreateBootstrapLogger();

var builder = WebApplication.CreateBuilder(args);

// Secrets live OUTSIDE the repo: appsettings.Secrets.json is gitignored. In production,
// set MASTER_USER / MASTER_PASS_HASH (or Auth:User / Auth:PassHash) as environment variables.
builder.Configuration.AddJsonFile("appsettings.Secrets.json", optional: true, reloadOnChange: true);

// --- Structured logging (Serilog) -----------------------------------------
// Console for operators + a daily-rolling application log file. The bespoke security
// audit log (ECS/CEF) is separate and owned by SecurityEventLog.
builder.Host.UseSerilog((ctx, cfg) => cfg
    .ReadFrom.Configuration(ctx.Configuration)
    .Enrich.FromLogContext()
    .Enrich.WithProperty("Application", "PacketSniffer")
    .WriteTo.Console()
    .WriteTo.File(
        path: Path.Combine("Logs", "app-.log"),
        rollingInterval: Serilog.RollingInterval.Day,
        retainedFileCountLimit: 14,
        rollOnFileSizeLimit: true,
        fileSizeLimitBytes: 50L * 1024 * 1024));

// --- Configuration & DI ---------------------------------------------------
var options = new SnifferOptions();
builder.Configuration.GetSection("Sniffer").Bind(options);
builder.Services.AddSingleton(options);
builder.Services.AddSingleton<FlowTracker>();
builder.Services.AddSingleton<PacketRingBuffer>();
builder.Services.AddSingleton<AlertStore>();
builder.Services.AddSingleton<BroadcastHub>();
builder.Services.AddSingleton<CaptureSession>();

// --- Bespoke security audit log -------------------------------------------
var securityLogOptions = new SecurityLogOptions();
builder.Configuration.GetSection("SecurityLog").Bind(securityLogOptions);
builder.Services.AddSingleton(securityLogOptions);
builder.Services.AddSingleton<SecurityEventLog>();

// --- Alert notifications (pluggable channels + background dispatcher) ------
var notifyOptions = new NotificationOptions();
builder.Configuration.GetSection("Notifications").Bind(notifyOptions);
builder.Services.AddSingleton(notifyOptions);
builder.Services.AddSingleton<NotificationQueue>();
builder.Services.AddHttpClient();

if (notifyOptions.Webhook.Enabled)
    builder.Services.AddSingleton<INotificationChannel>(sp =>
        new WebhookNotificationChannel(notifyOptions.Webhook, sp.GetRequiredService<IHttpClientFactory>()));
if (notifyOptions.Syslog.Enabled)
    builder.Services.AddSingleton<INotificationChannel>(_ => new SyslogNotificationChannel(notifyOptions.Syslog));
if (notifyOptions.Email.Enabled)
    builder.Services.AddSingleton<INotificationChannel>(_ => new EmailNotificationChannel(notifyOptions.Email));

builder.Services.AddHostedService<NotificationDispatcher>();

var app = builder.Build();

app.Urls.Clear();
app.Urls.Add(builder.Configuration["Urls"] ?? "http://0.0.0.0:5000");

app.UseSerilogRequestLogging();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(30) });

// Resolve credentials from environment variables first (production), then the gitignored
// secrets file (development). NOTHING is hardcoded here - if neither is set, auth fails closed.
var authUser = Environment.GetEnvironmentVariable("MASTER_USER") ?? builder.Configuration["Auth:User"];
var authHash = Environment.GetEnvironmentVariable("MASTER_PASS_HASH") ?? builder.Configuration["Auth:PassHash"];
if (string.IsNullOrEmpty(authUser) || string.IsNullOrEmpty(authHash))
    app.Logger.LogWarning(
        "No auth credentials configured. Set Auth:User/Auth:PassHash in appsettings.Secrets.json " +
        "or the MASTER_USER/MASTER_PASS_HASH environment variables. All requests will be rejected until then.");
Environment.SetEnvironmentVariable("MASTER_USER", authUser);
Environment.SetEnvironmentVariable("MASTER_PASS_HASH", authHash);

// --- Auth (HTTP Basic; ?auth= query is accepted for the WebSocket handshake) ----
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/health")) { await next(); return; }

    // Prefer the browser's cached Basic-auth header. Only fall back to the ?auth= query
    // param (used by the WebSocket handshake, which can't set headers) when none is present.
    if (string.IsNullOrEmpty(ctx.Request.Headers["Authorization"]))
    {
        var auth = ctx.Request.Query["auth"];
        if (!string.IsNullOrEmpty(auth))
            ctx.Request.Headers["Authorization"] = "Basic " + auth;
    }

    if (!Auth.Validate(ctx))
    {
        ctx.Response.Headers["WWW-Authenticate"] = "Basic realm=\"PacketSniffer\"";
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsync("Unauthorized");
        return;
    }
    await next();
});

// --- Endpoints ------------------------------------------------------------
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapGet("/devices", () =>
{
    var list = CaptureDeviceList.Instance.Select((d, i) => new
    {
        index = i,
        name = d.Name,
        description = d.Description
    });
    return Results.Json(list);
});

app.MapGet("/status", (CaptureSession session) => Results.Json(session.Status()));

app.MapPost("/start", (int devIndex, string? filter, CaptureSession session) =>
{
    try
    {
        var pcapPath = Path.Combine(Directory.GetCurrentDirectory(), "capture.pcap");
        var msg = session.Start(devIndex, filter, pcapPath);
        return Results.Ok(new { status = "started", device = devIndex, message = msg });
    }
    catch (InvalidOperationException ex) { return Results.Conflict(new { error = ex.Message }); }
    catch (ArgumentOutOfRangeException ex) { return Results.BadRequest(new { error = ex.Message }); }
    catch (Exception ex) { return Results.Problem(detail: ex.Message); }
});

app.MapPost("/stop", async (CaptureSession session) =>
{
    try { await session.StopAsync(); return Results.Ok(new { status = "stopped" }); }
    catch (InvalidOperationException ex) { return Results.BadRequest(new { error = ex.Message }); }
    catch (Exception ex) { return Results.Problem(detail: ex.Message); }
});

app.MapGet("/alerts", (AlertStore alerts) => Results.Json(alerts.Recent(500)));

// Full decode + hex dump for ONE packet, fetched on demand when the user clicks a row.
// This keeps the expensive human-readable rendering off the live broadcast path.
app.MapGet("/packet/{id:long}", (long id, PacketRingBuffer ring) =>
{
    var rec = ring.Get(id);
    if (rec == null) return Results.NotFound(new { error = "Packet expired from buffer or not found." });

    var parsed = PacketDecoder.TryParse(rec.LinkLayer, rec.Data);
    return Results.Json(new
    {
        id = rec.Id,
        timestamp = rec.TimestampUtc.ToLocalTime().ToString("o"),
        length = rec.Data.Length,
        src = rec.Src,
        dest = rec.Dest,
        protocol = rec.Protocol,
        verdict = rec.Verdict.ToString(),
        flowKey = rec.FlowKey,
        matches = rec.Matches.Select(m => new { m.Sid, m.Name, severity = m.Severity.ToString(), m.Category, m.Technique }),
        decode = parsed?.ToString() ?? "<undecodable>",
        hex = PacketDecoder.HexDump(rec.Data)
    });
});

app.MapGet("/download", () =>
{
    var pcapPath = Path.Combine(Directory.GetCurrentDirectory(), "capture.pcap");
    return File.Exists(pcapPath)
        ? Results.File(pcapPath, "application/vnd.tcpdump.pcap", "session.pcap")
        : Results.NotFound(new { error = "No capture file found. Start and stop a capture first." });
});

app.MapPost("/upload", async (HttpRequest req, CaptureSession session) =>
{
    if (!req.HasFormContentType || req.Form.Files.Count == 0)
        return Results.BadRequest(new { error = "No file uploaded." });

    var file = req.Form.Files[0];
    var tempFile = Path.GetTempFileName();
    await using (var stream = new FileStream(tempFile, FileMode.Create))
        await file.CopyToAsync(stream);

    // Replay through the same analysis pipeline on a background thread.
    _ = Task.Run(async () =>
    {
        try { await session.ReplayFileAsync(tempFile); }
        catch (Exception ex) { app.Logger.LogError(ex, "Upload replay error"); }
        finally { try { File.Delete(tempFile); } catch { } }
    });

    return Results.Ok(new { status = "processing_started" });
});

app.MapGet("/ws", async (HttpContext context, BroadcastHub hub) =>
{
    if (!context.WebSockets.IsWebSocketRequest) { context.Response.StatusCode = 400; return; }

    var socket = await context.WebSockets.AcceptWebSocketAsync();
    var id = Guid.NewGuid().ToString();
    hub.Register(id, socket);

    var buffer = new byte[4096];
    try
    {
        while (socket.State == WebSocketState.Open)
        {
            var result = await socket.ReceiveAsync(buffer, CancellationToken.None);
            if (result.MessageType == WebSocketMessageType.Close) break;
        }
    }
    catch { /* client dropped */ }
    finally
    {
        hub.Unregister(id);
        try { await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "closing", CancellationToken.None); } catch { }
    }
});

// Graceful teardown of the capture pipeline.
app.Lifetime.ApplicationStopping.Register(() =>
{
    var session = app.Services.GetRequiredService<CaptureSession>();
    session.DisposeAsync().AsTask().GetAwaiter().GetResult();
});

try
{
    // Touch the security log so a misconfiguration surfaces at startup, not on first alert.
    _ = app.Services.GetRequiredService<SecurityEventLog>();
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Host terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
