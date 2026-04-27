using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.Urls.Clear();
//app.Urls.Add("http://localhost:5000");
app.Urls.Add("http://0.0.0.0:5000");
app.UseDefaultFiles();
app.UseStaticFiles();

var webSocketOptions = new WebSocketOptions()
{ 
    KeepAliveInterval = TimeSpan.FromSeconds(30)
};

app.UseWebSockets(webSocketOptions);

var devices = CaptureDeviceList.Instance;
var captureDevice = (ICaptureDevice?)null;
PacketArrivalEventHandler? activeHandler = null;
CaptureFileWriterDevice? pcapWriter = null; 
var capturing = false;
var packetQueue = new ConcurrentQueue<object>();
var webSockets = new ConcurrentDictionary<string, WebSocket>();
var cts = new CancellationTokenSource();

Environment.SetEnvironmentVariable("MASTER_USER", "admin");
Environment.SetEnvironmentVariable("MASTER_PASS_HASH", "oK8Cs5GlW6+4d3d6Djkf4w==:LdkdAVpWdNKphLFID+ooc44iiibLcUFWLlUymmckH1A=");

// Simple async authenticator
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/health"))
    {
        await next();
        return;
    }

    if (!Auth.Validate(ctx))
    {
        ctx.Response.Headers["WWW-Authenticate"] = "Basic realms=\"PacketSniffer\"";
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsync("Unauthorized");
        return;
    }
    var auth = ctx.Request.Query["auth"];
    ctx.Request.Headers["Authorization"] = "Basic " + auth;
    await next();
});


_ = Task.Run(async () =>
{
    var token = cts.Token;

    while (!token.IsCancellationRequested)
    {
        while(packetQueue.TryDequeue(out var item))
        {
            var json = JsonSerializer.Serialize(item);
            var bytes = Encoding.UTF8.GetBytes(json);
            var tasks = webSockets.Values.Select(async ws =>
            {
                try
                {
                    await ws.SendAsync(bytes, WebSocketMessageType.Text, true, token);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex.Message);
                }
            });

            try{
                await Task.WhenAll(tasks);
            }
            catch {  }
        }

        await Task.Delay(50, token);
    }
});

app.MapGet("/devices", () =>
{
    var list = CaptureDeviceList.Instance.Select((d, i) => new
    {
        Index = i,
        Name = d.Name,
        Description = d.Description
    }).ToArray();
    return Results.Json(list);
});


// filters like so https://wiki.wireshark.org/CaptureFilters..

app.MapPost("/start", (int devIndex, string? filter) =>
{
    if (capturing) return Results.BadRequest(new { error = "Already capturing" });

    var devList = CaptureDeviceList.Instance;

    if (devIndex < 0 || devIndex >= devList.Count) return Results.BadRequest(new { error = "Invalid index of device" });

    var device = devList[devIndex];

    try
    {
        device.Open(DeviceModes.Promiscuous, 1000);
        if (!string.IsNullOrWhiteSpace(filter))
        {
            try { device.Filter = filter; } catch { /* ignore invalid filter */ }
        }
        
        // Open the PCAP writer
        var pcapFilePath = Path.Combine(Directory.GetCurrentDirectory(), "capture.pcap");
        pcapWriter = new CaptureFileWriterDevice(pcapFilePath);
        pcapWriter.Open(device);
    }
    catch(Exception ex) 
    {
        return Results.Problem(detail: ex.Message);
    }

    capturing = true;
    captureDevice = device as ICaptureDevice;
    var flowAnalyzer = new FlowAnalyzer();

    if (activeHandler != null)
    {
        device.OnPacketArrival -= activeHandler;
    }

    activeHandler = (sender, e) =>
    {
            try
            {
                // Write to PCAP file on arrival
                pcapWriter?.Write(e.GetPacket());

                var packet = e.GetPacket();
                var time = packet.Timeval.Date;
                var len = packet.Data.Length;

                // Attempt to parse packet data
                Packet? parsed = PacketDotNet.Packet.ParsePacket(packet.LinkLayerType, packet.Data);

                string? src = null, dest = null, proto = null;

                if (parsed is EthernetPacket eth)
                {
                    var ip = eth.PayloadPacket as IPPacket;

                    if (ip != null)
                    {
                        src = ip.SourceAddress.ToString();
                        dest = ip.DestinationAddress.ToString();
                        proto = ip.Protocol.ToString();

                        if (ip.PayloadPacket is TcpPacket tcp)
                            proto = $"TCP ({tcp.SourcePort}->{tcp.DestinationPort})";
                        else if (ip.PayloadPacket is UdpPacket udp)
                            proto = $"UDP ({udp.SourcePort}->{udp.DestinationPort})";
                        else if (ip.PayloadPacket is IcmpV4Packet icmp)
                            proto = "ICMP";
                    }
                    else if (eth.PayloadPacket != null)
                    {
                        // Non-IP payload (ARP, LLDP, etc.)
                        proto = eth.PayloadPacket.GetType().Name.Replace("Packet", "");
                    }
                }

                // Format raw bytes for view.
                string hexDump = BitConverter.ToString(packet.Data).Replace("-", " ");
                var verdict = Helpers.ClassifyPacket(parsed);
            

                var packetMsg = new
                {
                    type = "packet",
                    timestamp = time.ToLocalTime().ToString("o"),
                    length = len,
                    src,
                    dest,
                    protocol = proto,
                    raw = hexDump,
                    details = parsed.ToString(),
                    verdict = verdict.ToString()
                };

                var flowResult = flowAnalyzer.ProcessPacket(parsed);
                var flowVerdict = flowResult.Verdict;
                var flowSnapshot = flowResult.Snapshot;

                if (flowSnapshot != null)
                {
                    // only send when meaningful changes happen.
                    if(flowSnapshot.packetCount % 10 == 0)
                        packetQueue.Enqueue(flowSnapshot);
                }
                packetQueue.Enqueue(packetMsg);
            }
            catch (Exception ex)
            {
                packetQueue.Enqueue(new { timestamp = DateTime.Now.ToString("o"), error = ex.Message });
                Console.Error.WriteLine(ex.Message);
            }
    };

    device.OnPacketArrival += activeHandler; // Attach the new one safely

    device.StartCapture();
    return Results.Ok(new { status = "started", device = devIndex });
});

app.MapPost("/stop", () =>
{
    if (!capturing) return Results.BadRequest(new { error = "Not capturing" });
    try
    {
        captureDevice?.StopCapture();
        captureDevice?.Close();
        
        // Close and flush the pcap writer to disk
        pcapWriter?.Close();
        pcapWriter = null;
    }
    catch (Exception ex)
    {
        return Results.Problem(detail: ex.Message);
    }
    capturing = false;
    captureDevice = null;
    return Results.Ok(new { status = "stopped" });
});

app.MapGet("/", async context =>
{
    var path = Path.Combine(app.Environment.ContentRootPath, "wwwroot", "index.html");

    if (!File.Exists(path))
    {
        context.Response.StatusCode = 404;
        await context.Response.WriteAsync("Error: index.html not found.");
        return;
    }

    context.Response.ContentType = "text/html; charset=utf-8";
    var html = await System.IO.File.ReadAllTextAsync(path);
    await context.Response.WriteAsync(html);
});

app.MapGet("/ws", async context =>
{
    if (!context.WebSockets.IsWebSocketRequest)
    {
        context.Response.StatusCode = 400;
        return;
    }
    var socket = await context.WebSockets.AcceptWebSocketAsync();
    var id = Guid.NewGuid().ToString();
    webSockets[id] = socket;


    var buffer = new byte[1024 * 4];
    try
    {
        while (socket.State == WebSocketState.Open)
        {
            var result = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                break;
            }
            // ignore client messages for now
        }
    }
    catch { }
    finally
    {
        webSockets.TryRemove(id, out _);
        try { await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "closing", CancellationToken.None); } catch { }
    }
});

app.MapGet("/download", () =>
{
    var pcapPath = Path.Combine(Directory.GetCurrentDirectory(), "capture.pcap");
    if (!File.Exists(pcapPath))
    {
        return Results.NotFound(new { error = "No capture file found. Start and stop a capture first." });
    }
    
    return Results.File(pcapPath, "application/vnd.tcpdump.pcap", "session.pcap");
});

app.MapPost("/upload", async (HttpRequest req) =>
{
    if (!req.HasFormContentType || req.Form.Files.Count == 0)
        return Results.BadRequest(new { error = "No file uploaded." });

    var file = req.Form.Files[0];
    var tempFile = Path.GetTempFileName();

    await using (var stream = new FileStream(tempFile, FileMode.Create))
    {
        await file.CopyToAsync(stream);
    }

    // Process the PCAP on a background thread to prevent blocking the HTTP response
    _ = Task.Run(() =>
    {
        try
        {
            using var pcapDevice = new CaptureFileReaderDevice(tempFile);
            pcapDevice.Open();
            var offlineAnalyzer = new FlowAnalyzer();

            pcapDevice.OnPacketArrival += (sender, e) =>
            {
                var packet = e.GetPacket();
                var time = packet.Timeval.Date;
                var len = packet.Data.Length;

                Packet? parsed = PacketDotNet.Packet.ParsePacket(packet.LinkLayerType, packet.Data);
                string? src = null, dest = null, proto = parsed.GetType().Name;

                if (parsed is EthernetPacket eth)
                {
                    if (eth.PayloadPacket is IPPacket ip)
                    {
                        src = ip.SourceAddress.ToString();
                        dest = ip.DestinationAddress.ToString();
                        proto = ip.Protocol.ToString();
                        if (ip.PayloadPacket is TcpPacket tcp) proto += $" (TCP {tcp.SourcePort}->{tcp.DestinationPort})";
                        else if (ip.PayloadPacket is UdpPacket udp) proto += $" (UDP {udp.SourcePort}->{udp.DestinationPort})";
                    }
                    else if (eth.PayloadPacket != null)
                    {
                        proto = eth.PayloadPacket.GetType().Name;
                    }
                }

                var verdict = Helpers.ClassifyPacket(parsed);

                var packetMsg = new
                {
                    type = "packet",
                    timestamp = time.ToString("o"),
                    length = len,
                    src,
                    dest,
                    protocol = proto,
                    raw = packet.Data,
                    details = parsed.ToString(),
                    verdict = verdict.ToString()
                };

                var flowResult = offlineAnalyzer.ProcessPacket(parsed);
                if (flowResult.Snapshot != null && flowResult.Snapshot.packetCount % 10 == 0)
                    packetQueue.Enqueue(flowResult.Snapshot);

                packetQueue.Enqueue(packetMsg);

                // Slight delay keeps a 1GB file from instantly crashing the WebSocket buffer
                Thread.Sleep(1);
            };

            pcapDevice.Capture();
            pcapDevice.Close();
            File.Delete(tempFile);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Upload PCAP Error: " + ex.Message);
        }
    });

    return Results.Ok(new { status = "processing_started" });
});

app.Lifetime.ApplicationStopping.Register(() => cts.Cancel());

app.Run();
