using System.Collections.Concurrent;

namespace PacketSniffer.Core;

/// <summary>
/// Bounded, lock-free store of the most recent decoded packets, addressable by id.
/// The UI receives only lightweight <see cref="PacketSummary"/> rows; the full record
/// (raw bytes for the hex dump + decode tree) is fetched on demand by id when a user
/// clicks a row. This is the core reason the browser no longer hangs: we never push
/// kilobyte-scale decode strings for every frame.
/// </summary>
public sealed class PacketRingBuffer
{
    private readonly int _capacity;
    private readonly ConcurrentQueue<PacketRecord> _queue = new();
    private readonly ConcurrentDictionary<long, PacketRecord> _byId = new();
    private long _nextId;

    public PacketRingBuffer(SnifferOptions opt) => _capacity = Math.Max(1024, opt.RingBufferSize);

    public long NextId() => Interlocked.Increment(ref _nextId);

    public void Add(PacketRecord record)
    {
        _queue.Enqueue(record);
        _byId[record.Id] = record;

        while (_queue.Count > _capacity && _queue.TryDequeue(out var evicted))
            _byId.TryRemove(evicted.Id, out _);
    }

    public PacketRecord? Get(long id) => _byId.TryGetValue(id, out var r) ? r : null;

    public void Reset()
    {
        _byId.Clear();
        while (_queue.TryDequeue(out _)) { }
        Interlocked.Exchange(ref _nextId, 0);
    }

    public int Count => _byId.Count;
}
