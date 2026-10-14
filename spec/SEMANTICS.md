# SmartWatch semantics

This is the contract every engine follows: the Python reference (`src/sf_smartwatch`) and the ports in
`ports/`. The vectors in `spec/conformance/` test it; when this text and the vectors disagree, that is a
bug to report. All integers in documents and outputs are at most 2^53 − 1 (the largest integer every
JSON parser keeps exactly). Agent ids, environment names and level names are ASCII, so "sorted" always
means byte order.

## 1. What is measured

Agents send messages to each other. A **reporter** next to each agent (or a log ingester) tells the
monitor "agent `src` sent `count` messages to agent `dst` at time `ts_ms`". The monitor cuts time into
windows of `window_ms` and, for each window, counts:

- `messages`: messages between two different agents (a message from an agent to itself is not coupling;
  it is counted in `self_messages` only);
- `agents`: distinct agents that sent or received such a message;
- `pairs`: distinct **unordered** pairs {a, b} that exchanged at least one message;
- `possible_pairs` = agents × (agents − 1) / 2.

**Coupling density** is the average number of messages per possible pair per second, reported in
millionths (an integer, `density_micro`):

    density_micro = min(2^53 − 1, floor( (double(messages) × 1e9) / (double(possible_pairs) × double(window_ms)) ))
                    and 0 when possible_pairs = 0

computed in IEEE 754 doubles with exactly this order of operations (so every language gets the same
integer). 1e9 = 1e6 (micro) × 1000 (ms per second). Example: 5 agents (10 possible pairs) exchanging 200
messages in a 1 s window: 200 × 1e9 / (10 × 1000) = 20,000,000, that is 20 messages per pair per second.

`pair_ratio_micro` = min(1,000,000, floor(double(pairs) × 1e6 / double(possible_pairs))), 0 without
possible pairs: the share of pairs that talk at all (graph density). It is reported; it does not grade.

Density, not the raw message count, grades: it does not grow just because more agents join, and it
reads the same for any window length.

## 2. Events

An event is `{src, dst, ts_ms, count}`:

- `src`, `dst`: strings matching `[A-Za-z0-9._:@/-]{1,128}` (ASCII only);
- `ts_ms`: integer, 0 ≤ ts_ms ≤ 2^53 − 1 (milliseconds since the Unix epoch in practice);
- `count`: integer, 1 ≤ count ≤ 10^9.

Booleans are not integers, and `1.5` or `"1"` are not integers. An invalid event raises
`WATCH-BAD-EVENT` and changes nothing (no counter, no window). `flush(now_ms)` checks `now_ms` the same
way as `ts_ms`.

## 3. Policy

One JSON document (`spec/policy.schema.json`; vectors `policies.json`). Exactly these fields, no others,
and every nested object with exactly its fields:

| Field | Rule |
|---|---|
| `schema` | `"smartwatch.policy/v1"` |
| `environment` | matches the id pattern |
| `window_ms` | integer 100 … 60000 |
| `late_windows` | integer 0 … 60: how many windows stay open for late events |
| `max_empty_windows` | integer 0 … 3600: empty windows emitted after a silence before skipping |
| `min_agents` | integer 2 … 1,000,000: below this many agents a window is always `normal` |
| `levels` | 1 … 8 objects `{name, min_density_micro}`; names match `[a-z][a-z0-9_-]{0,31}`, unique, not `normal`; `min_density_micro` integer ≥ 1, strictly increasing |
| `hysteresis_permille` | integer 0 … 900 |
| `reset.level` | one of the level names |
| `reset.sustain_ms` | integer 0 … 3,600,000 |
| `reset.mode` | `auto`, `confirm` or `off` |
| `reset.confirm_timeout_ms` | integer 0 … 3,600,000 |
| `reset.on_timeout` | `reset` or `cancel` |
| `reset.cooldown_ms` | integer 0 … 86,400,000 |
| `reset.max_agents` | integer 1 … 1000 |
| `reset.hot_pair_min_count` | integer 1 … 10^9 |
| `limits.max_pairs_exact` | integer 1 … 10^7 |
| `limits.max_agents_exact` | integer 1 … 10^7 |
| `limits.top_k` | integer 1 … 100 |
| `limits.candidates` | integer 1 … 65536 |
| `hash_seed` | string of 1 … 256 UTF-8 bytes |

Any violation, including a value of the wrong JSON type anywhere, is `WATCH-BAD-POLICY`. The level order in `levels` is the grading order; index −1 means
`normal`.

## 4. Hashes

    fnv1a32(seed, text): FNV-1a 32 (offset 2166136261, prime 16777619) over UTF-8(seed) ‖ 0x00 ‖ UTF-8(text)
    fnv1a64(seed, text): FNV-1a 64 (offset 14695981039346656037, prime 1099511628211) over the same bytes
    mix64(h): h ^= h >> 33; h *= 0xFF51AFD7ED558CCD; h ^= h >> 33; h *= 0xC4CEB9FE1A85EC53; h ^= h >> 33
              (all modulo 2^64)

The text of a pair is `a + "\n" + b` with a < b. A pair's bucket is `fnv1a32(seed, text) mod 2^20`.
Vectors: `hashing.json` (64-bit values as decimal strings).

## 5. HyperLogLog (p = 14)

16,384 one-byte registers, all 0 at the start.

    add(x):     h = mix64(fnv1a64(seed, x)); j = h >> 50; w = h & (2^50 − 1)
                rho = 51 − bitlength(w)          (bitlength(0) = 0, so rho = 51 when w = 0)
                reg[j] = max(reg[j], rho)
    estimate(): count[v] = number of registers equal to v, for v = 0 … 51
                Z = 0.0; for v = 51 down to 0: if count[v] > 0: Z += count[v] × 2^−v       (doubles, this order)
                m = 16384; alpha = 0.7213 / (1 + 1.079 / m); E = alpha × m × m / Z
                if E ≤ 2.5 × m and count[0] > 0: E = m × ln(m / count[0])
                result = min(floor(E + 0.5), 2^53 − 1)
    digest():   lower-case hex SHA-256 of the 16,384 register bytes

Vectors: `hll.json` (an `items` value `{"prefix", "from", "to"}` means prefix + decimal i for from ≤ i < to).

## 6. The engine

State: `acc` (open windows by index), `next_emit` (null until the first event), `high`, `empties`,
`level` (−1), `streak_start` (null), `triggered` (false), `last_trigger` (null), and the counters
`events`, `messages`, `late_dropped`, `skipped_windows`, `windows` (all 0). Every counter except
`skipped_windows` and `windows` saturates: `sat(a, b) = min(2^53 − 1, a + b)`.

### add(src, dst, ts_ms, count)

    check the event (section 2)
    w = floor(ts_ms / window_ms)
    if next_emit is null: next_emit = w; high = w
    if w < next_emit: late_dropped = sat(late_dropped, count); return []          (the window has closed)
    events = sat(events, 1); messages = sat(messages, count)
    count it into acc[w] (created empty if missing)
    high = max(high, w)
    return close()

### flush(now_ms)

    check now_ms; if next_emit is null: return []
    high = max(high, floor(now_ms / window_ms)); return close()

### Counting into a window

A window keeps: `pairs` (exact map pair → count), `agents` (exact set), `total`, `self_messages`, and,
once a limit is reached, two HyperLogLogs (`hll_pairs`, `hll_agents`), 2^20 bucket counters and a
`cand` map (pair → estimate) with at most `limits.candidates` entries.

    if src == dst: self_messages = sat(self_messages, count); stop
    total = sat(total, count)
    for a in (src, dst):
        if a in agents: continue
        if agents_over: hll_agents.add(a)
        elif |agents| < max_agents_exact: agents.add(a)
        else: agents_over = true; hll_agents = new HLL(seed); add every agent of agents to it; hll_agents.add(a)
    key = (min(src, dst), max(src, dst)); text = key.a + "\n" + key.b
    if key in pairs: pairs[key] = sat(pairs[key], count); stop
    if not pairs_over and |pairs| < max_pairs_exact: pairs[key] = count; stop
    if not pairs_over: pairs_over = true; hll_pairs = new HLL(seed); add the text of every pair in pairs;
                       buckets = 2^20 zeros
    hll_pairs.add(text)
    i = fnv1a32(seed, text) mod 2^20; buckets[i] = sat(buckets[i], count); est = buckets[i]
    if key in cand or |cand| < candidates: cand[key] = est
    else: low = the entry of cand with the smallest (estimate, a, b)
          if (est, key.a, key.b) > (low.estimate, low.a, low.b): remove low; cand[key] = est

Pairs already in the exact map keep counting exactly after the limit; only new pairs go to the buckets.
A bucket can hold several pairs, so its estimate is at least the pair's true count (collisions only
over-count). A pair's estimate is updated only when a message of that pair arrives.

### Closing windows: close()

    out = []
    while next_emit + late_windows < high:
        w = next_emit
        if acc has w: remove it; empties = 0; out += emit(w, it); next_emit = w + 1
        elif empties < max_empty_windows: empties += 1; out += emit(w, empty window); next_emit = w + 1
        else:
            bound = high − late_windows
            nxt = the smallest of {k in acc with k ≥ w} ∪ {bound}
            skipped_windows += nxt − w; next_emit = nxt
            streak_start = null; triggered = false
            if level ≠ −1: out += {kind: "level", window: w, from: name(level), to: "normal", density_micro: 0}; level = −1
    return out

A window `w` therefore closes once an event or a flush reaches window `w + late_windows + 1`.

### emit(w, window)

    n = agents_over ? min(hll_agents.estimate(), 10^8) : |agents|
    possible = n × (n − 1) / 2
    distinct = pairs_over ? min(hll_pairs.estimate(), possible) : |pairs|
    density = density_micro(total, possible, window_ms); ratio as in section 1
    entries = [(count, a, b, exact: true) for each pair in pairs]
            + [(estimate, a, b, exact: false) for each pair in cand not in pairs]
    sort entries by count descending, then a, then b; top = the first top_k as {a, b, count, exact}
    windows += 1
    before = level; level = grade(density, n)
    out = [{kind: "window", window: w, start_ms: w × window_ms, messages: total, self_messages,
            agents: n, pairs: distinct, possible_pairs: possible, density_micro: density,
            pair_ratio_micro: ratio, exact: not (pairs_over or agents_over), level: name(level), top}]
    if level ≠ before: out += {kind: "level", window: w, from: name(before), to: name(level), density_micro: density}
    r = reset_due(w, top, density); if r: out += r

### grade(density, n)

    if n < min_agents: return −1
    raw = the highest index i with density ≥ levels[i].min_density_micro, or −1
    if raw ≥ level: return raw
    for j = level down to raw + 1:                       (falling: hysteresis)
        if density × 1000 ≥ levels[j].min_density_micro × (1000 − hysteresis_permille): return j
    return raw

The comparison uses exact integers (the product fits in 2^63 for every allowed value; use 128-bit or
big integers if your language has no 64-bit integers). Rising is immediate; falling needs the density
to drop below the threshold minus `hysteresis_permille` thousandths of it.

### reset_due(w, top, density)

    R = index of reset.level
    if level < R: streak_start = null; triggered = false; return null
    if streak_start is null: streak_start = w
    if mode == "off" or triggered: return null
    if (w − streak_start + 1) × window_ms < sustain_ms: return null
    if last_trigger not null and (w − last_trigger) × window_ms < cooldown_ms: return null
    triggered = true; last_trigger = w
    agents = []
    for t in top (in order): if t.count < hot_pair_min_count: stop
                             for a in (t.a, t.b): if a not in agents and |agents| < max_agents: append a
    return {kind: "reset", window: w, mode, level: name(level), density_micro: density,
            sustained_ms: (w − streak_start + 1) × window_ms, agents}

One reset per stay at or above the reset level: the level must fall below it before the next.
`agents` can be empty (no pair reached `hot_pair_min_count`); the service then records that and does
nothing else.

### snapshot()

    {level: name(level), next_window: next_emit (null before the first event), open_windows: |acc|,
     events, messages, late_dropped, skipped_windows, windows}

Outputs are JSON objects with exactly the fields above. The vectors (`monitor.json`) compare every step:
`add` and `flush` give `{ok: true, outputs: [...]}` or `{ok: false, code}`, `stats` gives the snapshot.

## 7. Calibration

    thresholds(densities, permille):
        refuse (error) if densities is empty, a density is not an integer ≥ 0 (1.5, true, "5" and −2 are
        refused), or a percentile is not an integer 1 … 1000
        xs = densities sorted ascending; prev = 0
        for p in permille: rank = ceil(p × N / 1000) (as (p × N + 999) div 1000); v = xs[max(rank, 1) − 1]
                           v = max(v, prev + 1, 1); output v; prev = v

Profiles: prod = [950, 990, 999] (p95, p99, p99.9), staging = [900, 950, 990]. Vectors: `calibration.json`.

## 8. Canonical JSON and the audit chain

Canonical JSON: object keys (ASCII) sorted byte-wise, no whitespace, `,` and `:` separators; strings in
UTF-8 with only `\"` `\\` `\b` `\f` `\n` `\r` `\t` and `\u00XX` (lower-case hex) for the other
characters below U+0020 escaped, everything else as is; integers only; `true`, `false`, `null`. A value
with a fractional number has no canonical form. Vectors: `canonical.json`.

Audit record n: the event's fields plus `seq` (= n), `ts_ms`, `event`, `prev` (the `hash` of record
n − 1, or 64 zeros for record 0); `hash` = lower-case hex SHA-256 of the canonical JSON of the record
without `hash`. `verify(records)` returns ok, or the index of the first record that is not an object, whose `seq` is not
the integer n (`true` and `1.0` are not integers), whose `prev` or `hash` is wrong, or which has no
canonical form. Vectors: `audit.json`.

## 9. The service (Python reference only)

Not part of the vectors; described in `docs/integration.md` and `spec/openapi.yaml`. In short: the
service feeds events to the engine, calls `flush(now)` every 100 ms, refuses events stamped more than
2 s ahead of its clock (`WATCH-CLOCK-SKEW`), counts events up to 2 s ahead at its own current time (so
that no reporter's clock can move the windows ahead of the monitor's), reports events for closed windows
as `WATCH-LATE`, turns `reset` outputs into reset commands (`auto`) or
proposals (`confirm`), times proposals out after `confirm_timeout_ms` (then `on_timeout`), and writes
every level change, proposal, decision, reset and acknowledgement to the audit chain.
