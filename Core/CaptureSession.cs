using System.Threading.Channels;
using PacketDotNet;
using PacketSniffer.Core.Logging;
using PacketSniffer.Core.Notifications;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PacketSniffer.Core;

/// <summary>
/// Orchestrates a single capture session. Architecture (decoupled producer/consumer):
///
///   [NIC] --OnPacketArrival--> (capture thread: write pcap + enqueue raw bytes)
///        --> bounded Channel (drop-oldest backpressure) -->
///   (analysis workers: decode once, run SignatureEngine + FlowTracker, store, broadcast)
///
/// The capture callback does NO decoding or serialization - that was the original hang.
/// Under a flood the channel drops the oldest frames rather than blocking the NIC reader
/// or exhausting memory; dropped counts are tracked and surfaced in /status.
/// </summary>
public sealed class CaptureSession : IAsyncDisposable
{
    private readonly SnifferOptions _opt;
    private readonly FlowTracker _flows;
    private readonly PacketRingBuffer _ring;
    private readonly AlertStore _alerts;
    private readonly BroadcastHub _hub;
    private readonly SecurityEventLog _securityLog;
    private readonly NotificationQueue _notifications;
    private readonly string _sensorHost = Environment.MachineName;

    private readonly object _gate = new();
    private ICaptureDevice? _device;
    private CaptureFileWriterDevice? _pcapWriter;
    private Channel<RawFrame>? _channel;
    private CancellationTokenSource? _cts;
    private Task? _workerTask;
    private Task? _janitorTask;
    private PacketArrivalEventHandler? _handler;

    private long _captured, _dropped, _analyzed, _errors;

    public CaptureSession(SnifferOptions opt, FlowTracker flows, PacketRingBuffer ring, AlertStore alerts,
        BroadcastHub hub, SecurityEventLog securityLog, NotificationQueue notifications)
    {
        _opt = opt; _flows = flows; _ring = ring; _alerts = alerts; _hub = hub;
        _securityLog = securityLog; _notifications = notifications;
    }

    public bool IsCapturing { get; private set; }
    public int? DeviceIndex { get; private set; }

    public object Status() => new
    {
        capturing = IsCapturing,
        device = DeviceIndex,
        captured = Interlocked.Read(ref _captured),
        analyzed = Interlocked.Read(ref _analyzed),
        dropped = Interlocked.Read(ref _dropped),
        errors = Interlocked.Read(ref _errors),
        activeFlows = _flows.ActiveFlows,
        ringBuffered = _ring.Count,
        clients = _hub.ClientCount
    };

    public string Start(int devIndex, string? filter, string pcapPath)
    {
        lock (_gate)
        {
            if (IsCapturing) throw new InvalidOperationException("Already capturing.");

            var devices = CaptureDeviceList.Instance;
            if (devIndex < 0 || devIndex >= devices.Count)
                throw new ArgumentOutOfRangeException(nameof(devIndex), "Invalid device index.");

            ResetState();

            var device = devices[devIndex];
            device.Open(DeviceModes.Promiscuous, 1000);
            if (!string.IsNullOrWhiteSpace(filter))
                device.Filter = filter; // throws on bad BPF - surfaced to caller

            _pcapWriter = new CaptureFileWriterDevice(pcapPath);
            _pcapWriter.Open(device);

            _cts = new CancellationTokenSource();
            _channel = Channel.CreateBounded<RawFrame>(
                new BoundedChannelOptions(_opt.CaptureChannelCapacity)
                {
                    FullMode = BoundedChannelFullMode.DropOldest,
                    SingleReader = true,
                    SingleWriter = true
                },
                // Called when an old frame is evicted under flood - count it as dropped.
                _ => Interlocked.Increment(ref _dropped));

            _handler = OnPacketArrival;
            device.OnPacketArrival += _handler;
            _device = device;

            _workerTask = Task.Run(() => AnalysisLoopAsync(_channel.Reader, _cts.Token));
            _janitorTask = Task.Run(() => JanitorLoopAsync(_cts.Token));

            device.StartCapture();
            IsCapturing = true;
            DeviceIndex = devIndex;
            return $"Capturing on device {devIndex}.";
        }
    }

    // Capture thread: stay minimal. Persist to pcap, then hand raw bytes to the pipeline.
    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var raw = e.GetPacket();
            _pcapWriter?.Write(raw);
            Interlocked.Increment(ref _captured);

            // DropOldest never fails the write; evicted frames are counted via the
            // itemDropped callback registered on the channel.
            _channel!.Writer.TryWrite(new RawFrame(raw, false));
        }
        catch
        {
            Interlocked.Increment(ref _errors);
        }
    }

    private async Task AnalysisLoopAsync(ChannelReader<RawFrame> reader, CancellationToken ct)
    {
        try
        {
            await foreach (var frame in reader.ReadAllAsync(ct))
                Analyze(frame.Capture);
        }
        catch (OperationCanceledException) { /* normal shutdown */ }
    }

    /// <summary>Decode + detect a single frame. Shared by live capture and offline replay.</summary>
    public void Analyze(RawCapture raw)
    {
        try
        {
            var parsed = PacketDecoder.TryParse(raw.LinkLayerType, raw.Data);
            if (parsed == null) { Interlocked.Increment(ref _errors); return; }

            var nowUtc = raw.Timeval.Date.ToUniversalTime();
            var l = PacketDecoder.Extract(parsed);

            var sigMatches = SignatureEngine.Inspect(parsed);
            var flow = _flows.Process(parsed, nowUtc);

            // Combine stateless signatures with stateful flow findings for the packet verdict.
            var all = sigMatches.Count == 0
                ? flow.Matches
                : flow.Matches.Count == 0 ? sigMatches : sigMatches.Concat(flow.Matches).ToList();

            var verdict = VerdictMapping.VerdictOf(all);
            long id = _ring.NextId();

            _ring.Add(new PacketRecord
            {
                Id = id,
                TimestampUtc = nowUtc,
                LinkLayer = raw.LinkLayerType,
                Data = raw.Data,
                Src = l.SrcIp?.ToString(),
                Dest = l.DstIp?.ToString(),
                Protocol = l.Display,
                Verdict = verdict,
                Matches = all,
                FlowKey = flow.Snapshot?.Key
            });

            _hub.QueuePacket(new PacketSummary(
                id, nowUtc.ToLocalTime().ToString("o"),
                l.SrcIp?.ToString(), l.DstIp?.ToString(), l.Display,
                raw.Data.Length, verdict.ToString(), all.Count > 0));

            if (flow.Snapshot != null && flow.SnapshotChangedMeaningfully)
                _hub.QueueFlow(flow.Snapshot);

            foreach (var rule in all)
            {
                var alert = _alerts.TryRecord(rule, nowUtc, l.SrcIp?.ToString(), l.DstIp?.ToString(), l.Display);
                if (alert == null) continue; // suppressed repeat

                _hub.QueueAlert(alert);

                // Fan the (un-suppressed) alert to the bespoke audit log and the
                // notification dispatcher. Both are non-blocking on this thread: the log
                // write is rare (suppression-throttled) and Notify only enqueues.
                var ctx = new AlertContext(l.SrcPort, l.DstPort, l.Protocol, raw.Data.Length, nowUtc, _sensorHost);
                _securityLog.Record(alert, ctx);
                _notifications.Notify(alert, ctx);
            }

            Interlocked.Increment(ref _analyzed);
        }
        catch
        {
            Interlocked.Increment(ref _errors);
        }
    }

    private async Task JanitorLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(30), ct);
                _flows.Sweep(DateTime.UtcNow);
            }
        }
        catch (OperationCanceledException) { }
    }

    public async Task StopAsync()
    {
        Task? worker, janitor;
        lock (_gate)
        {
            if (!IsCapturing) throw new InvalidOperationException("Not capturing.");

            if (_device != null && _handler != null) _device.OnPacketArrival -= _handler;
            try { _device?.StopCapture(); } catch { }
            try { _device?.Close(); } catch { }

            _channel?.Writer.TryComplete();
            _cts?.Cancel();
            worker = _workerTask; janitor = _janitorTask;

            try { _pcapWriter?.Close(); } catch { }
            _pcapWriter = null;
            _device = null;
            IsCapturing = false;
        }

        // Let the worker drain remaining buffered frames before we report stopped.
        if (worker != null) try { await worker; } catch { }
        if (janitor != null) try { await janitor; } catch { }
    }

    /// <summary>Offline replay of an uploaded capture file through the same analysis path.</summary>
    public Task ReplayFileAsync(string path, CancellationToken ct = default) => Task.Run(() =>
    {
        using var reader = new CaptureFileReaderDevice(path);
        reader.Open();
        reader.OnPacketArrival += (_, e) =>
        {
            if (ct.IsCancellationRequested) return;
            Analyze(e.GetPacket());
        };
        reader.Capture();
        reader.Close();
    }, ct);

    private void ResetState()
    {
        Interlocked.Exchange(ref _captured, 0);
        Interlocked.Exchange(ref _dropped, 0);
        Interlocked.Exchange(ref _analyzed, 0);
        Interlocked.Exchange(ref _errors, 0);
        _flows.Reset();
        _ring.Reset();
        _alerts.Reset();
        _hub.Reset();
    }

    public async ValueTask DisposeAsync()
    {
        try { if (IsCapturing) await StopAsync(); } catch { }
        _cts?.Dispose();
    }
}
