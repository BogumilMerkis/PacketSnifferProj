using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace PacketSniffer.Core;

/// <summary>
/// Owns all connected WebSocket clients and pushes coalesced state on a fixed timer
/// instead of forwarding every packet immediately. Three things make the UI keep up
/// under load:
///   1. Packet summaries are buffered and flushed as ONE batch per tick (default 250ms).
///   2. Flow snapshots are coalesced by key - only the latest state per flow is sent.
///   3. The batch is serialized once and the same byte buffer is fanned out to every client.
/// Buffers are bounded; under a flood the oldest pending summaries are dropped (the ring
/// buffer still holds them for on-demand inspection), so memory can't run away.
/// </summary>
public sealed class BroadcastHub : IAsyncDisposable
{
    private readonly SnifferOptions _opt;
    private readonly ILogger<BroadcastHub> _log;
    private readonly ConcurrentDictionary<string, WebSocket> _clients = new();

    private readonly ConcurrentQueue<PacketSummary> _packets = new();
    private readonly ConcurrentDictionary<string, FlowSnapshotDto> _flows = new();
    private readonly ConcurrentQueue<Alert> _alerts = new();

    private readonly Timer _timer;
    private int _flushing;

    // Match ASP.NET minimal-API defaults (camelCase) so the WebSocket protocol and the
    // REST responses use identical property names on the wire.
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    public BroadcastHub(SnifferOptions opt, ILogger<BroadcastHub> log)
    {
        _opt = opt;
        _log = log;
        _timer = new Timer(_ => _ = FlushAsync(), null,
            opt.BroadcastIntervalMs, opt.BroadcastIntervalMs);
    }

    public void Register(string id, WebSocket socket) => _clients[id] = socket;
    public void Unregister(string id) => _clients.TryRemove(id, out _);
    public int ClientCount => _clients.Count;

    public void QueuePacket(PacketSummary s)
    {
        _packets.Enqueue(s);
        // Bound the pending buffer; drop-oldest under flood (full record stays in ring buffer).
        while (_packets.Count > _opt.MaxPacketsPerBatch * 4 && _packets.TryDequeue(out _)) { }
    }

    public void QueueFlow(FlowSnapshotDto f) => _flows[f.Key] = f; // coalesce: latest wins
    public void QueueAlert(Alert a)
    {
        _alerts.Enqueue(a);
        while (_alerts.Count > _opt.MaxAlertsPerBatch * 4 && _alerts.TryDequeue(out _)) { }
    }

    private async Task FlushAsync()
    {
        // Re-entrancy guard: a slow flush must not overlap the next timer tick.
        if (Interlocked.Exchange(ref _flushing, 1) == 1) return;
        try
        {
            if (_clients.IsEmpty)
            {
                DrainAll();
                return;
            }

            var packets = Drain(_packets, _opt.MaxPacketsPerBatch);
            var flows = DrainFlows(_opt.MaxFlowsPerBatch);
            var alerts = Drain(_alerts, _opt.MaxAlertsPerBatch);

            if (packets.Count == 0 && flows.Count == 0 && alerts.Count == 0)
                return;

            var batch = new
            {
                type = "batch",
                packets,
                flows,
                alerts,
                stats = new { clients = _clients.Count }
            };

            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(batch, JsonOpts);
            await FanOutAsync(bytes);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Broadcast flush error");
        }
        finally
        {
            Interlocked.Exchange(ref _flushing, 0);
        }
    }

    private async Task FanOutAsync(byte[] bytes)
    {
        var seg = new ArraySegment<byte>(bytes);
        var dead = new List<string>();

        foreach (var (id, ws) in _clients)
        {
            if (ws.State != WebSocketState.Open) { dead.Add(id); continue; }
            try
            {
                await ws.SendAsync(seg, WebSocketMessageType.Text, true, CancellationToken.None);
            }
            catch
            {
                dead.Add(id);
            }
        }
        foreach (var id in dead) _clients.TryRemove(id, out _);
    }

    private static List<T> Drain<T>(ConcurrentQueue<T> q, int max)
    {
        var list = new List<T>(Math.Min(max, q.Count));
        while (list.Count < max && q.TryDequeue(out var item)) list.Add(item);
        return list;
    }

    private List<FlowSnapshotDto> DrainFlows(int max)
    {
        var list = new List<FlowSnapshotDto>();
        foreach (var key in _flows.Keys)
        {
            if (list.Count >= max) break;
            if (_flows.TryRemove(key, out var f)) list.Add(f);
        }
        return list;
    }

    private void DrainAll()
    {
        while (_packets.TryDequeue(out _)) { }
        while (_alerts.TryDequeue(out _)) { }
        _flows.Clear();
    }

    public void Reset() => DrainAll();

    public async ValueTask DisposeAsync()
    {
        await _timer.DisposeAsync();
        foreach (var (_, ws) in _clients)
        {
            try { await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "shutdown", CancellationToken.None); }
            catch { /* client already gone */ }
        }
    }
}
