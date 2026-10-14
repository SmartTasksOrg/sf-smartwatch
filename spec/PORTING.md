# Porting SmartWatch

A port is the **engine and the agent side** in another language: the deterministic engine of
`SEMANTICS.md` (so a team can run the monitor's arithmetic in-process, replay traffic or check the
reference), plus a reporter and a command poller that talk to the Python monitor over HTTP. The HTTP
monitor itself (proposals, webhooks, audit file, JWT) stays in Python. Read `SEMANTICS.md` first; the
vectors in `conformance/` are the test.

## What a port contains

1. **Canonical JSON** encoder over the language's parsed JSON values (`canonical.json`).
2. **FNV-1a 32/64 and mix64** with unsigned 64-bit arithmetic (`hashing.json`).
3. **HyperLogLog** p = 14 exactly as specified, including the summation order (`hll.json`).
4. **density_micro** in IEEE doubles, in the given order of operations (`density.json`).
5. **Policy validation** (`policies.json`).
6. **Calibration thresholds** (`calibration.json`).
7. **The engine**: add / flush / snapshot with the outputs of SEMANTICS.md section 6 (`monitor.json`).
8. **Audit chain verification** (`audit.json`).
9. **A reporter**: `record(src, dst, count = 1)` adds to an in-memory map keyed by
   (src, dst, ts_ms − ts_ms mod 1000) and never blocks on the network; a background loop sends the map
   every 1 s ± up to 200 ms of random jitter as `POST /v1/events` with body `{"events": [...]}` (at most
   10,000 events per request, sorted by time, then src, then dst), `Authorization: Bearer <token>` and
   `Content-Type: application/json` (every POST needs it; never send an `Origin` header).
   When the request fails on the network or with a 5xx, the events are put back and sent next time; when
   the monitor answers 400/401/403/413 they are dropped and counted as refused. At most 100,000 keys are
   kept; beyond that, messages are counted as dropped. `close()` stops the loop and sends what is left.
   A 200 or 207 answer is `{"accepted": n, "rejected": [{"index", "code", "error"}]}`: messages accepted
   are the counts of the events not listed in `rejected` (codes `WATCH-BAD-EVENT`, `WATCH-CLOCK-SKEW`,
   `WATCH-LATE`).
10. **A command poller** for one agent: every `interval` send `GET /v1/agents/{id}/commands` (the id
    percent-encoded: `/` as `%2F`); for each command `{"type": "reset", "reset_id", "reason",
    "created_ms"}` call the handler, and when it returns normally send `POST /v1/resets/{reset_id}/ack`
    with body `{"agent_id": "<id>"}`. A handler that throws: no acknowledgement (the command comes again).
11. **A conformance runner** (`<runner> <vectors dir>`): prints failures and a last line
    `<port>: N/N vectors passed`, exit 1 on any failure. N must equal the Python count (1468).
12. **An interop program** for `ports/conformance/interop.py` (below).

## How each vector file is checked (exactly what the Python runner does)

One check per case, except `monitor.json` (one check per step).

- `canonical.json`: `canonical(input)` equals `canonical` and the SHA-256 of its UTF-8 bytes equals `sha256`.
- `hashing.json`: `{fnv1a32, fnv1a64 (decimal string), mix64 (decimal string of mix64(fnv1a64)), bucket}`
  equals the case's values.
- `hll.json`: new HLL with `seed`; add every item (expanding `{"prefix","from","to"}`); compare
  `{estimate, digest}`.
- `density.json`: `density_micro(messages, possible_pairs, window_ms)` equals `density_micro`.
- `policies.json`: `{ok: true}` or `{ok: false, code}` compared with the case's `ok` and `code` (when present).
- `calibration.json`: `{ok: true, thresholds}` or `{ok: false}` (compare `ok`, and `thresholds` when present).
- `monitor.json`: a new engine with `policy`; each step `add` → `{ok: true, outputs}` or `{ok: false, code}`,
  `flush` likewise, `stats` → the snapshot; compare with `expect`.
- `audit.json`: `{ok, index}` (index null when ok) equals `result`.

Comparisons are of JSON values: key order does not matter, integers compare as integers, `true` is not 1.

## The interop program

Started as `<program> URL AGENT_IDS SECONDS` with the ingest token in `SMARTWATCH_INGEST_TOKEN`.
`AGENT_IDS` is a comma-separated list (one may contain `/`).

- Start the reporter, and one command poller per agent with a 200 ms interval. For every command
  received print `RESET <agent_id> <reset_id>` (one line, flushed) and acknowledge it.
- For SECONDS × 10 rounds, one every 100 ms: for every ordered pair (a, b) of different agents, `record(a, b, 1)`.
- Then close the reporter (sending everything) and print `SENT <messages accepted>` (flushed).
- Keep polling and printing until standard input closes, then exit 0. Errors go to standard error.

`interop.py` runs the Python monitor with an auto-reset policy that these rounds trip, checks that the
monitor counted exactly the messages the program says it sent, that every agent of the burst received
and acknowledged its reset, and that a reset sent by hand (with a JWT) to the agent whose id contains
`/` arrives and is acknowledged.

## Pitfalls

- 64-bit unsigned arithmetic: FNV-64 and mix64 need wrap-around multiplication modulo 2^64. Java and PHP
  have only signed 64-bit integers: the bits are the same, only printing and shifting differ (use
  logical shifts: `>>>` in Java; in PHP mask after `>>`, and multiply in 32-bit halves because PHP turns
  an overflowing integer product into a float). JavaScript: use BigInt for the 64-bit hashes.
- `grade` compares `density × 1000` with `threshold × (1000 − h)`: both stay below 2^63 but above 2^53,
  so JavaScript needs BigInt (or an exact reformulation) here.
- The HLL estimate and the density must be computed in doubles in the specified order; do not "simplify"
  `(m × 1e9) / (p × w)` into `m / p × 1e6 / w`.
- `ln` in `m × ln(m / V)`: the platform's natural logarithm on doubles. All engines so far agree on every
  vector; if yours differs in the last bit, report it.
- Sorting: ids are ASCII, compare them byte-wise (not locale-aware). `top` sorts by count descending,
  then a, then b; the candidate eviction compares (estimate, a, b) ascending.
- The bucket array is 2^20 unsigned counters, allocated only when a window goes over the exact limit.
- Late events: an event for a window that has already been emitted adds its count to `late_dropped` and
  does not count in `events` or `messages`.
- Open a new connection per request or reuse one, either is fine; never follow redirects (they would
  carry the bearer token elsewhere).
