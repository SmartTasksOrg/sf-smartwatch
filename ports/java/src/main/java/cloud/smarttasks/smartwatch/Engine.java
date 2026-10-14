package cloud.smarttasks.smartwatch;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The SmartWatch engine (spec/SEMANTICS.md section 6): counts messages between agents per window, computes
 * the coupling density, grades it and decides when a reset is due. Deterministic: time comes only from the
 * events and from {@link #flush(long)}. Not thread-safe; callers synchronize.
 *
 * <p>Outputs are {@code LinkedHashMap<String, Object>} with {@code Long}, {@code String}, {@code Boolean} and
 * {@code List} values, in the order of the reference: each closed window, then its level change and reset.
 */
public final class Engine {
    public static final long MAX_INT = 9007199254740991L; // 2^53 - 1
    public static final int BUCKETS = 1 << 20;
    public static final long MICRO = 1_000_000L;
    public static final long MAX_AGENTS = 100_000_000L;
    public static final long MAX_COUNT = 1_000_000_000L;

    /** min(2^53 - 1, a + b) for non-negative a, b at most 2^53 - 1. */
    public static long sat(long a, long b) { return Math.min(MAX_INT, a + b); }

    /** min(2^53 - 1, floor(d)) for a finite non-negative double, the long range guarded. */
    static long floorCap(double d) {
        double f = Math.floor(d);
        return f >= (double) MAX_INT ? MAX_INT : (long) f;
    }

    /** min(2^53-1, floor((double(messages) * 1e9) / (double(possible) * double(windowMs)))), 0 without pairs. */
    public static long densityMicro(long messages, long possiblePairs, long windowMs) {
        if (possiblePairs <= 0) return 0;
        return floorCap(((double) messages * 1e9) / ((double) possiblePairs * (double) windowMs));
    }

    static WatchError badEvent(String msg) { return new WatchError("WATCH-BAD-EVENT", msg); }

    /** Check an event's fields (spec section 2); throws WatchError(WATCH-BAD-EVENT). */
    public static void checkEvent(String src, String dst, long tsMs, long count) {
        if (src == null || dst == null || !Policy.ID.matcher(src).matches() || !Policy.ID.matcher(dst).matches()) {
            throw badEvent("src and dst must match [A-Za-z0-9._:@/-]{1,128}");
        }
        if (tsMs < 0 || tsMs > MAX_INT) throw badEvent("ts_ms must be an integer from 0 to 2^53 - 1");
        if (count < 1 || count > MAX_COUNT) throw badEvent("count must be an integer from 1 to 10^9");
    }

    /** {@link #add(String, String, long, long)} on parsed JSON values: a non-string id, or a value that is
     *  not a JSON integer (a Boolean, a Double such as 1.5), is WATCH-BAD-EVENT. */
    public List<Map<String, Object>> addValues(Object src, Object dst, Object tsMs, Object count) {
        if (!(src instanceof String s) || !(dst instanceof String d)) throw badEvent("src and dst must match [A-Za-z0-9._:@/-]{1,128}");
        if (!Policy.ID.matcher(s).matches() || !Policy.ID.matcher(d).matches()) throw badEvent("src and dst must match [A-Za-z0-9._:@/-]{1,128}");
        if (!(tsMs instanceof Long t)) throw badEvent("ts_ms must be an integer from 0 to 2^53 - 1");
        if (!(count instanceof Long c)) throw badEvent("count must be an integer from 1 to 10^9");
        return add(s, d, t, c);
    }

    /** {@link #flush(long)} on a parsed JSON value. */
    public List<Map<String, Object>> flushValue(Object nowMs) {
        if (!(nowMs instanceof Long n)) throw badEvent("now_ms must be an integer from 0 to 2^53 - 1");
        return flush(n);
    }

    private static final class Window {
        final HashMap<String, Long> pairs = new HashMap<>();   // key: a + "\n" + b with a < b
        final HashSet<String> agents = new HashSet<>();
        long total;
        long selfMessages;
        long[] buckets;
        final HashMap<String, Long> cand = new HashMap<>();
        // candidates ordered by (estimate, a, b); "a\nb" orders as (a, b) because '\n' is below every id byte
        final TreeSet<Cand> order = new TreeSet<>();
        HyperLogLog hllPairs;
        HyperLogLog hllAgents;
        boolean pairsOver;
        boolean agentsOver;
    }

    private record Cand(long est, String key) implements Comparable<Cand> {
        public int compareTo(Cand o) {
            int c = Long.compare(est, o.est);
            return c != 0 ? c : key.compareTo(o.key);
        }
    }

    public final Policy policy;
    private final int resetIdx;
    private final TreeMap<Long, Window> acc = new TreeMap<>();
    private Long nextEmit;
    private long high;
    private long empties;
    private int level = -1;
    private Long streakStart;
    private boolean triggered;
    private Long lastTrigger;
    private long events, messages, lateDropped, skippedWindows, windows;

    public Engine(Policy policy) {
        this.policy = policy;
        this.resetIdx = policy.levelIndex(policy.resetLevel);
    }

    /** Count {@code count} messages from src to dst at ts_ms; returns the outputs of the windows it closed. */
    public List<Map<String, Object>> add(String src, String dst, long tsMs, long count) {
        checkEvent(src, dst, tsMs, count);
        long w = tsMs / policy.windowMs;
        if (nextEmit == null) {
            nextEmit = w;
            high = w;
        }
        if (w < nextEmit) {
            lateDropped = sat(lateDropped, count);
            return new ArrayList<>();
        }
        events = sat(events, 1);
        messages = sat(messages, count);
        Window a = acc.computeIfAbsent(w, k -> new Window());
        count(a, src, dst, count);
        if (w > high) high = w;
        return close();
    }

    /** Close the windows the clock says are complete. */
    public List<Map<String, Object>> flush(long nowMs) {
        if (nowMs < 0 || nowMs > MAX_INT) throw badEvent("now_ms must be an integer from 0 to 2^53 - 1");
        if (nextEmit == null) return new ArrayList<>();
        long w = nowMs / policy.windowMs;
        if (w > high) high = w;
        return close();
    }

    private void count(Window a, String src, String dst, long count) {
        if (src.equals(dst)) {
            a.selfMessages = sat(a.selfMessages, count);
            return;
        }
        a.total = sat(a.total, count);
        for (String x : new String[] {src, dst}) {
            if (a.agents.contains(x)) continue;
            if (a.agentsOver) {
                a.hllAgents.add(x);
            } else if (a.agents.size() < policy.maxAgentsExact) {
                a.agents.add(x);
            } else {
                a.agentsOver = true;
                a.hllAgents = new HyperLogLog(policy.hashSeed);
                for (String y : a.agents) a.hllAgents.add(y);
                a.hllAgents.add(x);
            }
        }
        String key = src.compareTo(dst) < 0 ? src + "\n" + dst : dst + "\n" + src;
        Long have = a.pairs.get(key);
        if (have != null) {
            a.pairs.put(key, sat(have, count));
            return;
        }
        if (!a.pairsOver && a.pairs.size() < policy.maxPairsExact) {
            a.pairs.put(key, count);
            return;
        }
        if (!a.pairsOver) {
            a.pairsOver = true;
            a.hllPairs = new HyperLogLog(policy.hashSeed);
            for (String k : a.pairs.keySet()) a.hllPairs.add(k);
            a.buckets = new long[BUCKETS];
        }
        a.hllPairs.add(key);
        int i = Hashing.bucket(policy.hashSeed, key);
        a.buckets[i] = sat(a.buckets[i], count);
        long est = a.buckets[i];
        Long old = a.cand.get(key);
        if (old != null || a.cand.size() < policy.candidates) {
            if (old != null) a.order.remove(new Cand(old, key));
            a.cand.put(key, est);
            a.order.add(new Cand(est, key));
        } else {
            Cand low = a.order.first();
            Cand mine = new Cand(est, key);
            if (mine.compareTo(low) > 0) {
                a.order.pollFirst();
                a.cand.remove(low.key());
                a.cand.put(key, est);
                a.order.add(mine);
            }
        }
    }

    private List<Map<String, Object>> close() {
        List<Map<String, Object>> out = new ArrayList<>();
        while (nextEmit + policy.lateWindows < high) {
            long w = nextEmit;
            Window a = acc.remove(w);
            if (a != null) {
                empties = 0;
                emit(out, w, a);
                nextEmit = w + 1;
            } else if (empties < policy.maxEmptyWindows) {
                empties++;
                emit(out, w, new Window());
                nextEmit = w + 1;
            } else {
                long bound = high - policy.lateWindows;
                Long k = acc.ceilingKey(w);
                long nxt = k != null && k < bound ? k : bound;
                skippedWindows += nxt - w;
                nextEmit = nxt;
                streakStart = null;
                triggered = false;
                if (level != -1) {
                    out.add(obj("kind", "level", "window", w, "from", name(level), "to", "normal", "density_micro", 0L));
                    level = -1;
                }
            }
        }
        return out;
    }

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int k = 0; k < kv.length; k += 2) m.put((String) kv[k], kv[k + 1]);
        return m;
    }

    private record Entry(long count, String key, boolean exact) {}

    private void emit(List<Map<String, Object>> out, long w, Window a) {
        windows++;
        long n = a.agentsOver ? Math.min(a.hllAgents.estimate(), MAX_AGENTS) : a.agents.size();
        long possible = n * (n - 1) / 2;
        long distinct = a.pairsOver ? Math.min(a.hllPairs.estimate(), possible) : a.pairs.size();
        long density = densityMicro(a.total, possible, policy.windowMs);
        long ratio = possible > 0 ? Math.min(MICRO, floorCap((double) distinct * 1e6 / (double) possible)) : 0;
        List<Entry> entries = new ArrayList<>(a.pairs.size() + a.cand.size());
        for (Map.Entry<String, Long> e : a.pairs.entrySet()) entries.add(new Entry(e.getValue(), e.getKey(), true));
        for (Map.Entry<String, Long> e : a.cand.entrySet()) {
            if (!a.pairs.containsKey(e.getKey())) entries.add(new Entry(e.getValue(), e.getKey(), false));
        }
        entries.sort((x, y) -> {
            int c = Long.compare(y.count(), x.count());
            return c != 0 ? c : x.key().compareTo(y.key());
        });
        List<Map<String, Object>> top = new ArrayList<>();
        for (int k = 0; k < entries.size() && k < policy.topK; k++) {
            Entry e = entries.get(k);
            int nl = e.key().indexOf('\n');
            top.add(obj("a", e.key().substring(0, nl), "b", e.key().substring(nl + 1), "count", e.count(), "exact", e.exact()));
        }
        int before = level;
        level = grade(density, n);
        String nm = name(level);
        out.add(obj("kind", "window", "window", w, "start_ms", w * policy.windowMs, "messages", a.total,
            "self_messages", a.selfMessages, "agents", n, "pairs", distinct, "possible_pairs", possible,
            "density_micro", density, "pair_ratio_micro", ratio, "exact", !(a.pairsOver || a.agentsOver),
            "level", nm, "top", top));
        if (level != before) out.add(obj("kind", "level", "window", w, "from", name(before), "to", nm, "density_micro", density));
        Map<String, Object> r = resetDue(w, top, density);
        if (r != null) out.add(r);
    }

    private String name(int i) { return i < 0 ? "normal" : policy.levels.get(i).name(); }

    private int grade(long density, long agents) {
        if (agents < policy.minAgents) return -1;
        int raw = -1;
        for (int i = 0; i < policy.levels.size(); i++) {
            if (density >= policy.levels.get(i).minDensityMicro()) raw = i;
        }
        if (raw >= level) return raw;
        long h = policy.hysteresisPermille;
        for (int j = level; j > raw; j--) {
            // both products stay below 2^63 for every allowed value
            if (density * 1000 >= policy.levels.get(j).minDensityMicro() * (1000 - h)) return j;
        }
        return raw;
    }

    private Map<String, Object> resetDue(long w, List<Map<String, Object>> top, long density) {
        if (level < resetIdx) {
            streakStart = null;
            triggered = false;
            return null;
        }
        if (streakStart == null) streakStart = w;
        if (policy.resetMode.equals("off") || triggered) return null;
        long sustained = (w - streakStart + 1) * policy.windowMs;
        if (sustained < policy.sustainMs) return null;
        if (lastTrigger != null && (w - lastTrigger) * policy.windowMs < policy.cooldownMs) return null;
        triggered = true;
        lastTrigger = w;
        List<Object> agents = new ArrayList<>();
        for (Map<String, Object> t : top) {
            if ((Long) t.get("count") < policy.hotPairMinCount) break;
            for (String x : new String[] {(String) t.get("a"), (String) t.get("b")}) {
                if (!agents.contains(x) && agents.size() < policy.resetMaxAgents) agents.add(x);
            }
        }
        return obj("kind", "reset", "window", w, "mode", policy.resetMode, "level", name(level), "density_micro", density,
            "sustained_ms", sustained, "agents", agents);
    }

    /** {level, next_window, open_windows, events, messages, late_dropped, skipped_windows, windows}. */
    public Map<String, Object> snapshot() {
        return obj("level", name(level), "next_window", nextEmit, "open_windows", (long) acc.size(), "events", events,
            "messages", messages, "late_dropped", lateDropped, "skipped_windows", skippedWindows, "windows", windows);
    }
}
