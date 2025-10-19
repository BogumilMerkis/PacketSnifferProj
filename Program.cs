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
app.Urls.Add("http://localhost:5000");
app.UseDefaultFiles();
app.UseStaticFiles();

var webSocketOptions = new WebSocketOptions()
{ 
    KeepAliveInterval = TimeSpan.FromSeconds(30)
};

app.UseWebSockets(webSocketOptions);

var devices = CaptureDeviceList.Instance;
var captureDevice = (ICaptureDevice?)null;
var capturing = false;
var packetQueue = new ConcurrentQueue<object>();
var webSockets = new ConcurrentDictionary<string, WebSocket>();
var cts = new CancellationTokenSource();

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
    }
    catch(Exception ex) 
    {
        return Results.Problem(detail: ex.Message);
    }

    capturing = true;
    captureDevice = device as ICaptureDevice;

    device.OnPacketArrival += (sender, e) =>
    {
        try
        {
            var packet = e.GetPacket();
            var time = packet.Timeval.Date;
            var len = packet.Data.Length;

            // Attempt to parse packet data
            var parsed = PacketDotNet.Packet.ParsePacket(packet.LinkLayerType, packet.Data);

            string? src = null, dest = null, proto = parsed.GetType().Name;

            if (parsed is EthernetPacket eth)
            {
                var ip = eth.PayloadPacket as IPPacket;

                if (ip != null)
                {
                    src = ip.SourceAddress.ToString();
                    dest = ip.DestinationAddress.ToString();
                    proto = ip.Protocol.ToString();

                    if (ip.PayloadPacket is TcpPacket tcp)
                        proto += $" (TCP {tcp.SourcePort}->{tcp.DestinationPort})";
                    else if (ip.PayloadPacket is UdpPacket udp)
                        proto += $" (UDP {udp.SourcePort}->{udp.DestinationPort})";
                }
                // Non-IP payload (ARP, etc.)
                if (eth.PayloadPacket != null)
                {
                    proto = eth.PayloadPacket.GetType().Name;
                }
            }

            var info = new
            {
                timestamp = time.ToString("o"),
                length = len,
                src,
                dest,
                protocol = proto
            };
            packetQueue.Enqueue(info);
        }
        catch (Exception ex)
        {
            packetQueue.Enqueue(new { timestamp = DateTime.UtcNow.ToString("o"), error = ex.Message });
            Console.Error.WriteLine(ex.Message);
        }
    };
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
    var path = "";
    if (app.Environment.IsProduction())
    {
        path = "C:\\Users\\Bogumil\\OneDrive - University of Huddersfield\\Year 4\\FYP\\PacketSniffer\\wwwroot\\index.html";
    }
    else
    {
        path = Path.Combine(app.Environment.ContentRootPath, "wwwroot", "index.html");

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


app.Lifetime.ApplicationStopping.Register(() => cts.Cancel());

app.Run();
