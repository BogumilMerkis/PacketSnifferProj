public class FlowSnapshot
{
	public string type { get; init; } = "flow";
	public string key { get; init; } = "";

	public string src { get; init; } = "";
	public string dest { get; init; } = "";
	public string protocol { get; init; } = "";

	public long packetCount { get; init; }
	public long byteCount { get; init; }

	public int syn { get; init; }
	public int fin { get; init; }
	public int rst { get; init; }

	public double duration { get; init; }
	public string verdict { get; init; } = "";
	public long lastSeen { get; init; }
}