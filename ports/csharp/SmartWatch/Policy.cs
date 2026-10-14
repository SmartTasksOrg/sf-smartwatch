using System.Text;

namespace SmartWatch;

/// <summary>A policy violation (code WATCH-BAD-POLICY).</summary>
public sealed class PolicyException : Exception
{
    public const string ErrorCode = "WATCH-BAD-POLICY";
    public string Code => ErrorCode;
    public PolicyException(string message) : base(message) { }
}

public sealed record Level(string Name, long MinDensityMicro);

public sealed record ResetRule(string Level, long SustainMs, string Mode, long ConfirmTimeoutMs, string OnTimeout,
    long CooldownMs, long MaxAgents, long HotPairMinCount);

public sealed record Limits(long MaxPairsExact, long MaxAgentsExact, long TopK, long Candidates);

/// <summary>A validated policy document (spec/SEMANTICS.md, section 3).</summary>
public sealed class Policy
{
    /// <summary>The default policy of the Python reference. Its thresholds are placeholders: calibrate them on your
    /// own traffic (spec/SEMANTICS.md, section 7).</summary>
    public const string DefaultJson = """
        {"schema": "smartwatch.policy/v1", "environment": "default", "window_ms": 1000,
         "late_windows": 2, "max_empty_windows": 10, "min_agents": 3,
         "levels": [{"name": "elevated", "min_density_micro": 2000000}, {"name": "high", "min_density_micro": 5000000},
                    {"name": "critical", "min_density_micro": 10000000}],
         "hysteresis_permille": 100,
         "reset": {"level": "critical", "sustain_ms": 5000, "mode": "confirm", "confirm_timeout_ms": 5000, "on_timeout": "reset",
                   "cooldown_ms": 60000, "max_agents": 10, "hot_pair_min_count": 1},
         "limits": {"max_pairs_exact": 100000, "max_agents_exact": 50000, "top_k": 10, "candidates": 1024},
         "hash_seed": "default/smartwatch"}
        """;

    public const long MaxInt = (1L << 53) - 1;

    public string Environment { get; }
    public long WindowMs { get; }
    public long LateWindows { get; }
    public long MaxEmptyWindows { get; }
    public long MinAgents { get; }
    public IReadOnlyList<Level> Levels { get; }
    public long HysteresisPermille { get; }
    public ResetRule Reset { get; }
    public Limits Limits { get; }
    public string HashSeed { get; }

    static readonly string[] Fields = { "schema", "environment", "window_ms", "late_windows", "max_empty_windows", "min_agents",
        "levels", "hysteresis_permille", "reset", "limits", "hash_seed" };
    static readonly string[] ResetFields = { "level", "sustain_ms", "mode", "confirm_timeout_ms", "on_timeout", "cooldown_ms",
        "max_agents", "hot_pair_min_count" };
    static readonly string[] LimitFields = { "max_pairs_exact", "max_agents_exact", "top_k", "candidates" };

    /// <summary><c>[A-Za-z0-9._:@/-]{1,128}</c>: agent ids and environment names.</summary>
    public static bool IsId(string? s) =>
        s != null && s.Length >= 1 && s.Length <= 128 && s.All(c => c < 0x80 && (char.IsAsciiLetterOrDigit(c) || "._:@/-".Contains(c)));

    /// <summary><c>[a-z][a-z0-9_-]{0,31}</c>: level names.</summary>
    public static bool IsLevelName(string? s) =>
        s != null && s.Length >= 1 && s.Length <= 32 && char.IsAsciiLetterLower(s[0]) &&
        s.Skip(1).All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '_' || c == '-');

    static long Int(object? v, long lo, long hi, string name) =>
        v is long l && l >= lo && l <= hi ? l : throw new PolicyException($"{name} must be an integer from {lo} to {hi}");

    /// <summary>Validate a parsed policy document (see <see cref="Json.Parse"/>); throws <see cref="PolicyException"/>.</summary>
    public Policy(object? doc)
    {
        if (!Json.HasExactly(doc, Fields)) throw new PolicyException("the policy must have exactly the fields of spec/SEMANTICS.md, section 3");
        object? G(string k) => Json.Get(doc, k);
        if (G("schema") is not string schema || schema != "smartwatch.policy/v1") throw new PolicyException("schema must be \"smartwatch.policy/v1\"");
        if (G("environment") is not string env || !IsId(env)) throw new PolicyException("environment must match [A-Za-z0-9._:@/-]{1,128}");
        Environment = env;
        WindowMs = Int(G("window_ms"), 100, 60000, "window_ms");
        LateWindows = Int(G("late_windows"), 0, 60, "late_windows");
        MaxEmptyWindows = Int(G("max_empty_windows"), 0, 3600, "max_empty_windows");
        MinAgents = Int(G("min_agents"), 2, 1_000_000, "min_agents");
        HysteresisPermille = Int(G("hysteresis_permille"), 0, 900, "hysteresis_permille");
        if (G("levels") is not List<object?> lv || lv.Count < 1 || lv.Count > 8) throw new PolicyException("levels must be a list of 1 to 8 levels");
        var levels = new List<Level>();
        long prev = 0;
        foreach (var x in lv)
        {
            if (!Json.HasExactly(x, "name", "min_density_micro")) throw new PolicyException("each level must be {\"name\", \"min_density_micro\"}");
            if (Json.Get(x, "name") is not string name || !IsLevelName(name) || name == "normal" || levels.Any(l => l.Name == name))
                throw new PolicyException("level names must match [a-z][a-z0-9_-]{0,31}, be unique and not \"normal\"");
            var min = Int(Json.Get(x, "min_density_micro"), 1, MaxInt, "min_density_micro");
            if (min <= prev) throw new PolicyException("min_density_micro must be strictly increasing from level to level");
            prev = min;
            levels.Add(new Level(name, min));
        }
        Levels = levels;
        var r = G("reset");
        if (!Json.HasExactly(r, ResetFields)) throw new PolicyException("reset must have exactly the fields of spec/SEMANTICS.md, section 3");
        if (Json.Get(r, "level") is not string rl || !levels.Any(l => l.Name == rl)) throw new PolicyException("reset.level must be one of the level names");
        if (Json.Get(r, "mode") is not string mode || (mode != "auto" && mode != "confirm" && mode != "off"))
            throw new PolicyException("reset.mode must be auto, confirm or off");
        if (Json.Get(r, "on_timeout") is not string ot || (ot != "reset" && ot != "cancel"))
            throw new PolicyException("reset.on_timeout must be reset or cancel");
        Reset = new ResetRule(rl,
            Int(Json.Get(r, "sustain_ms"), 0, 3_600_000, "reset.sustain_ms"), mode,
            Int(Json.Get(r, "confirm_timeout_ms"), 0, 3_600_000, "reset.confirm_timeout_ms"), ot,
            Int(Json.Get(r, "cooldown_ms"), 0, 86_400_000, "reset.cooldown_ms"),
            Int(Json.Get(r, "max_agents"), 1, 1000, "reset.max_agents"),
            Int(Json.Get(r, "hot_pair_min_count"), 1, 1_000_000_000, "reset.hot_pair_min_count"));
        var li = G("limits");
        if (!Json.HasExactly(li, LimitFields)) throw new PolicyException("limits must have exactly the fields of spec/SEMANTICS.md, section 3");
        Limits = new Limits(
            Int(Json.Get(li, "max_pairs_exact"), 1, 10_000_000, "limits.max_pairs_exact"),
            Int(Json.Get(li, "max_agents_exact"), 1, 10_000_000, "limits.max_agents_exact"),
            Int(Json.Get(li, "top_k"), 1, 100, "limits.top_k"),
            Int(Json.Get(li, "candidates"), 1, 65536, "limits.candidates"));
        int seedBytes;
        try { seedBytes = G("hash_seed") is string hs ? new UTF8Encoding(false, true).GetByteCount(hs) : -1; }
        catch (EncoderFallbackException) { seedBytes = -1; }
        if (seedBytes < 1 || seedBytes > 256) throw new PolicyException("hash_seed must be a string of 1 to 256 UTF-8 bytes");
        HashSeed = (string)G("hash_seed")!;
    }

    /// <summary>The default policy (<see cref="DefaultJson"/>).</summary>
    public static Policy Default() => new(Json.Parse(DefaultJson));

    /// <summary>Read and validate a policy file.</summary>
    public static Policy Load(string path)
    {
        object? doc;
        try { doc = Json.Parse(File.ReadAllText(path)); }
        catch (System.Text.Json.JsonException e) { throw new PolicyException($"{path}: not JSON ({e.Message})"); }
        return new Policy(doc);
    }

    /// <summary>Index of a level name in <see cref="Levels"/>, or -1 ("normal" or unknown).</summary>
    public int LevelIndex(string name)
    {
        for (var i = 0; i < Levels.Count; i++) if (Levels[i].Name == name) return i;
        return -1;
    }
}
