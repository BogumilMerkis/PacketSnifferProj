namespace PacketSniffer.Core;

/// <summary>
/// Minimal MITRE ATT&amp;CK (Enterprise) lookup for the technique IDs the detection
/// engine emits. Lets the structured log enrich a bare technique ID (e.g. "T1046")
/// with its canonical name, parent tactic, and attack.mitre.org reference URLs so
/// downstream SIEMs can pivot by kill-chain phase (tactic) or behaviour (technique).
///
/// Tactic mappings follow ATT&amp;CK v19 (April 2026). Note: in v19 the tactic TA0005
/// was renamed from "Defense Evasion" to "Stealth" - the name below reflects that.
/// </summary>
public static class MitreAttack
{
    public const string Framework = "MITRE ATT&CK";

    public sealed record TechniqueInfo(
        string TechniqueId, string TechniqueName, string TacticId, string TacticName);

    // Keyed by the exact technique/sub-technique ID used in the rule definitions.
    private static readonly Dictionary<string, TechniqueInfo> Techniques = new()
    {
        ["T1046"]     = new("T1046", "Network Service Discovery",            "TA0007", "Discovery"),
        ["T1071"]     = new("T1071", "Application Layer Protocol",           "TA0011", "Command and Control"),
        ["T1190"]     = new("T1190", "Exploit Public-Facing Application",    "TA0001", "Initial Access"),
        ["T1048"]     = new("T1048", "Exfiltration Over Alternative Protocol","TA0010", "Exfiltration"),
        ["T1048.003"] = new("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol", "TA0010", "Exfiltration"),
        ["T1499"]     = new("T1499", "Endpoint Denial of Service",           "TA0040", "Impact"),
        ["T1499.001"] = new("T1499.001", "Endpoint Denial of Service: OS Exhaustion Flood", "TA0040", "Impact"),
        ["T1557"]     = new("T1557", "Adversary-in-the-Middle",              "TA0006", "Credential Access"),
        ["T1557.002"] = new("T1557.002", "ARP Cache Poisoning",             "TA0006", "Credential Access"),
        ["T1599"]     = new("T1599", "Network Boundary Bridging",            "TA0005", "Stealth"),
    };

    /// <summary>Returns the enrichment for a technique ID, or null if it isn't a known ID.</summary>
    public static TechniqueInfo? Lookup(string? techniqueId)
    {
        if (string.IsNullOrEmpty(techniqueId)) return null;
        if (Techniques.TryGetValue(techniqueId, out var info)) return info;
        // Fall back to the parent technique when only a sub-technique mapping is missing.
        var dot = techniqueId.IndexOf('.');
        if (dot > 0 && Techniques.TryGetValue(techniqueId[..dot], out var parent))
            return parent with { TechniqueId = techniqueId };
        return null;
    }

    /// <summary>Canonical attack.mitre.org URL for a technique (sub-technique uses a slash, e.g. /T1499/001/).</summary>
    public static string TechniqueUrl(string techniqueId)
    {
        var path = techniqueId.Replace('.', '/');
        return $"https://attack.mitre.org/techniques/{path}/";
    }

    public static string TacticUrl(string tacticId) => $"https://attack.mitre.org/tactics/{tacticId}/";
}
