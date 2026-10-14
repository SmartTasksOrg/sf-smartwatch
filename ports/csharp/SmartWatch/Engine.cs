namespace SmartWatch;

/// <summary>An invalid event or flush time (code WATCH-BAD-EVENT); the engine is unchanged.</summary>
public sealed class EventException : Exception
{
    public const string ErrorCode = "WATCH-BAD-EVENT";
    public string Code => ErrorCode;
    public EventException(string message) : base(message) { }
}

/// <summary>
/// The SmartWatch engine (spec/SEMANTICS.md, sections 1, 2 and 6): count messages between agents per window, compute
/// the coupling density, grade it and decide when a reset is due. Deterministic: time comes from the events and from
/// <see cref="Flush"/>. Not thread-safe: use it from one thread or lock around it.
/// <code>
/// var eng = new Engine(Policy.Default());
/// var outputs = eng.Add("planner", "coder", 1700000000123, 4);   // often empty
/// outputs = eng.Flush(nowMs);                                     // close windows by the clock
/// </code>
/// Outputs are JSON objects (<see cref="SortedDictionary{TKey,TValue}"/>, see <see cref="Json"/>) with exactly the
/// fields of spec/SEMANTICS.md: <c>kind</c> "window", "level" or "reset".
/// </summary>
public sealed class Engine
{
    public const long MaxInt = (1L << 53) - 1;
    /// <summary>2^20 bucket counters, allocated when a window goes over limits.max_pairs_exact.</summary>
    public const int Buckets = 1 << 20;
    /// <summary>An agent estimate above this is reported as this (keeps n(n-1)/2 below 2^53).</summary>
    public const long MaxAgents = 100_000_000;
    const long Micro = 1_000_000;

    sealed class OrdinalTriple : IComparer<(long Est, string A, string B)>
    {
        public static readonly OrdinalTriple Instance = new();
        public int Compare((long Est, string A, string B) x, (long Est, string A, string B) y)
        {
            var c = x.Est.CompareTo(y.Est);
            if (c != 0) return c;
            c = string.CompareOrdinal(x.A, y.A);
            return c != 0 ? c : string.CompareOrdinal(x.B, y.B);
        }
    }

    sealed class Window
    {
        public readonly Dictionary<(string A, string B), long> Pairs = new();
        public readonly HashSet<string> Agents = new(StringComparer.Ordinal);
        public long Total, SelfMessages;
        public long[]? BucketCounts;
        public readonly Dictionary<(string A, string B), long> Cand = new();
        public readonly SortedSet<(long Est, string A, string B)> Order = new(OrdinalTriple.Instance);
        public HyperLogLog? HllPairs, HllAgents;
        public bool PairsOver, AgentsOver;
    }

    readonly Policy policy;
    readonly int resetIdx;
    readonly SortedDictionary<long, Window> acc = new();
    long? nextEmit;
    long high, empties;
    int level = -1;
    long? streakStart;
    bool triggered;
    long? lastTrigger;
    long events, messages, lateDropped, skippedWindows, windows;

    public Engine(Policy policy)
    {
        this.policy = policy;
        resetIdx = policy.LevelIndex(policy.Reset.Level);
    }

    public Policy Policy => policy;

    /// <summary>Saturating add at 2^53 − 1.</summary>
    public static long Sat(long a, long b) => Math.Min(MaxInt, a + b);

    /// <summary>min(2^53 − 1, floor((double(messages) × 1e9) / (double(possible) × double(window_ms)))), 0 without pairs.</summary>
    public static long DensityMicro(long messages, long possiblePairs, long windowMs)
    {
        if (possiblePairs <= 0) return 0;
        var d = Math.Floor(((double)messages * 1e9) / ((double)possiblePairs * (double)windowMs));
        return d >= MaxInt ? MaxInt : (long)d;
    }

    /// <summary>Check an event (spec/SEMANTICS.md, section 2); throws <see cref="EventException"/>.</summary>
    public static void CheckEvent(string? src, string? dst, long tsMs, long count)
    {
        if (!Policy.IsId(src) || !Policy.IsId(dst)) throw new EventException("src and dst must match [A-Za-z0-9._:@/-]{1,128}");
        if (tsMs < 0 || tsMs > MaxInt) throw new EventException("ts_ms must be an integer from 0 to 2^53 - 1");
        if (count < 1 || count > 1_000_000_000) throw new EventException("count must be an integer from 1 to 10^9");
    }

    /// <summary>Count <paramref name="count"/> messages from src to dst at tsMs; the outputs of the windows it closed.</summary>
    public List<SortedDictionary<string, object?>> Add(string src, string dst, long tsMs, long count = 1)
    {
        CheckEvent(src, dst, tsMs, count);
        var w = tsMs / policy.WindowMs;
        if (nextEmit == null)
        {
            nextEmit = w;
            high = w;
        }
        if (w < nextEmit.Value)
        {
            lateDropped = Sat(lateDropped, count);
            return new();
        }
        events = Sat(events, 1);
        messages = Sat(messages, count);
        if (!acc.TryGetValue(w, out var win)) acc[w] = win = new Window();
        CountInto(win, src, dst, count);
        if (w > high) high = w;
        return Close();
    }

    /// <summary>Close the windows the clock says are complete (also when no event arrives).</summary>
    public List<SortedDictionary<string, object?>> Flush(long nowMs)
    {
        if (nowMs < 0 || nowMs > MaxInt) throw new EventException("now_ms must be an integer from 0 to 2^53 - 1");
        if (nextEmit == null) return new();
        high = Math.Max(high, nowMs / policy.WindowMs);
        return Close();
    }

    /// <summary>{level, next_window, open_windows, events, messages, late_dropped, skipped_windows, windows}.</summary>
    public SortedDictionary<string, object?> Snapshot() => Json.Obj(
        ("level", Name(level)), ("next_window", nextEmit), ("open_windows", (long)acc.Count), ("events", events),
        ("messages", messages), ("late_dropped", lateDropped), ("skipped_windows", skippedWindows), ("windows", windows));

    string Name(int i) => i < 0 ? "normal" : policy.Levels[i].Name;

    static string Text((string A, string B) k) => k.A + "\n" + k.B;

    void CountInto(Window acc, string src, string dst, long count)
    {
        if (src == dst)
        {
            acc.SelfMessages = Sat(acc.SelfMessages, count);
            return;
        }
        var lim = policy.Limits;
        var seed = policy.HashSeed;
        acc.Total = Sat(acc.Total, count);
        foreach (var a in new[] { src, dst })
        {
            if (acc.Agents.Contains(a)) continue;
            if (acc.AgentsOver) acc.HllAgents!.Add(a);
            else if (acc.Agents.Count < lim.MaxAgentsExact) acc.Agents.Add(a);
            else
            {
                acc.AgentsOver = true;
                acc.HllAgents = new HyperLogLog(seed);
                foreach (var x in acc.Agents) acc.HllAgents.Add(x);
                acc.HllAgents.Add(a);
            }
        }
        var key = string.CompareOrdinal(src, dst) < 0 ? (src, dst) : (dst, src);
        if (acc.Pairs.TryGetValue(key, out var have))
        {
            acc.Pairs[key] = Sat(have, count);
            return;
        }
        if (!acc.PairsOver && acc.Pairs.Count < lim.MaxPairsExact)
        {
            acc.Pairs[key] = count;
            return;
        }
        var text = Text(key);
        if (!acc.PairsOver)
        {
            acc.PairsOver = true;
            acc.HllPairs = new HyperLogLog(seed);
            foreach (var k in acc.Pairs.Keys) acc.HllPairs.Add(Text(k));
            acc.BucketCounts = new long[Buckets];
        }
        acc.HllPairs!.Add(text);
        var i = Hashing.Bucket(seed, text);
        acc.BucketCounts![i] = Sat(acc.BucketCounts[i], count);
        var est = acc.BucketCounts[i];
        if (acc.Cand.TryGetValue(key, out var old))
        {
            acc.Order.Remove((old, key.Item1, key.Item2));
            acc.Order.Add((est, key.Item1, key.Item2));
            acc.Cand[key] = est;
        }
        else if (acc.Cand.Count < lim.Candidates)
        {
            acc.Order.Add((est, key.Item1, key.Item2));
            acc.Cand[key] = est;
        }
        else
        {
            var low = acc.Order.Min;
            if (OrdinalTriple.Instance.Compare((est, key.Item1, key.Item2), low) > 0)
            {
                acc.Order.Remove(low);
                acc.Cand.Remove((low.A, low.B));
                acc.Order.Add((est, key.Item1, key.Item2));
                acc.Cand[key] = est;
            }
        }
    }

    List<SortedDictionary<string, object?>> Close()
    {
        var outv = new List<SortedDictionary<string, object?>>();
        var late = policy.LateWindows;
        while (nextEmit!.Value + late < high)
        {
            var w = nextEmit.Value;
            if (acc.Remove(w, out var win))
            {
                empties = 0;
                Emit(w, win, outv);
                nextEmit = w + 1;
            }
            else if (empties < policy.MaxEmptyWindows)
            {
                empties++;
                Emit(w, new Window(), outv);
                nextEmit = w + 1;
            }
            else
            {
                var bound = high - late;
                var nxt = bound;
                foreach (var k in acc.Keys)
                    if (k >= w) { nxt = Math.Min(k, bound); break; }
                skippedWindows += nxt - w;
                nextEmit = nxt;
                streakStart = null;
                triggered = false;
                if (level != -1)
                {
                    outv.Add(Json.Obj(("kind", "level"), ("window", w), ("from", Name(level)), ("to", "normal"), ("density_micro", 0L)));
                    level = -1;
                }
            }
        }
        return outv;
    }

    void Emit(long w, Window acc, List<SortedDictionary<string, object?>> outv)
    {
        windows++;
        var n = acc.AgentsOver ? Math.Min(acc.HllAgents!.Estimate(), MaxAgents) : acc.Agents.Count;
        var possible = n * (n - 1) / 2;
        var distinct = acc.PairsOver ? Math.Min(acc.HllPairs!.Estimate(), possible) : acc.Pairs.Count;
        var density = DensityMicro(acc.Total, possible, policy.WindowMs);
        var ratio = possible > 0 ? Math.Min(Micro, (long)Math.Floor((double)distinct * 1e6 / (double)possible)) : 0;
        var entries = new List<(long Count, string A, string B, bool Exact)>();
        foreach (var kv in acc.Pairs) entries.Add((kv.Value, kv.Key.A, kv.Key.B, true));
        foreach (var kv in acc.Cand) if (!acc.Pairs.ContainsKey(kv.Key)) entries.Add((kv.Value, kv.Key.A, kv.Key.B, false));
        entries.Sort((x, y) =>
        {
            var c = y.Count.CompareTo(x.Count);
            if (c != 0) return c;
            c = string.CompareOrdinal(x.A, y.A);
            return c != 0 ? c : string.CompareOrdinal(x.B, y.B);
        });
        var top = entries.Take((int)policy.Limits.TopK).ToList();
        var before = level;
        level = Grade(density, n);
        var name = Name(level);
        outv.Add(Json.Obj(("kind", "window"), ("window", w), ("start_ms", w * policy.WindowMs), ("messages", acc.Total),
            ("self_messages", acc.SelfMessages), ("agents", n), ("pairs", distinct), ("possible_pairs", possible),
            ("density_micro", density), ("pair_ratio_micro", ratio), ("exact", !(acc.PairsOver || acc.AgentsOver)),
            ("level", name),
            ("top", top.Select(t => (object?)Json.Obj(("a", t.A), ("b", t.B), ("count", t.Count), ("exact", t.Exact))).ToList())));
        if (level != before)
            outv.Add(Json.Obj(("kind", "level"), ("window", w), ("from", Name(before)), ("to", name), ("density_micro", density)));
        var r = ResetDue(w, top, density);
        if (r != null) outv.Add(r);
    }

    int Grade(long density, long agents)
    {
        if (agents < policy.MinAgents) return -1;
        var levels = policy.Levels;
        var raw = -1;
        for (var i = 0; i < levels.Count; i++)
            if (density >= levels[i].MinDensityMicro) raw = i;
        if (raw >= level) return raw;
        var h = (Int128)policy.HysteresisPermille;
        for (var j = level; j > raw; j--)
            if ((Int128)density * 1000 >= (Int128)levels[j].MinDensityMicro * (1000 - h)) return j;
        return raw;
    }

    SortedDictionary<string, object?>? ResetDue(long w, List<(long Count, string A, string B, bool Exact)> top, long density)
    {
        var r = policy.Reset;
        if (level < resetIdx)
        {
            streakStart = null;
            triggered = false;
            return null;
        }
        streakStart ??= w;
        if (r.Mode == "off" || triggered) return null;
        var sustained = (w - streakStart.Value + 1) * policy.WindowMs;
        if (sustained < r.SustainMs) return null;
        if (lastTrigger != null && (w - lastTrigger.Value) * policy.WindowMs < r.CooldownMs) return null;
        triggered = true;
        lastTrigger = w;
        var agents = new List<object?>();
        foreach (var t in top)
        {
            if (t.Count < r.HotPairMinCount) break;
            foreach (var a in new[] { t.A, t.B })
                if (!agents.Contains(a) && agents.Count < r.MaxAgents) agents.Add(a);
        }
        return Json.Obj(("kind", "reset"), ("window", w), ("mode", r.Mode), ("level", Name(level)), ("density_micro", density),
            ("sustained_ms", sustained), ("agents", agents));
    }
}
