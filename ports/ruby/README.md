# SmartWatch for Ruby

This is the Ruby port of SmartWatch. It implements the engine of `spec/SEMANTICS.md` and the agent side of
`spec/PORTING.md`:

- canonical JSON and SHA-256
- seeded FNV-1a 32/64 and mix64
- HyperLogLog (p = 14)
- `density_micro`
- policy validation
- calibration thresholds
- the engine: `add`, `flush`, `snapshot`
- audit chain verification
- a reporter (`POST /v1/events`) and a command poller (`GET /v1/agents/{id}/commands`, then the acknowledgement)

The HTTP monitor itself (proposals, webhooks, the audit file, JWT) stays in Python.

It needs Ruby 3.2 or newer and is tested here with Ruby 3.3.6. It uses only the standard library and default
gems: `json`, `digest`, `net/http`, `openssl` and `uri`.

It is not published on RubyGems. The gemspec's `allowed_push_host` blocks `gem push`. Use it from a clone with
`ruby -Iports/ruby/lib` or `require_relative`.

## Layout

| Path | Contents |
|---|---|
| `lib/smartwatch.rb` | everything, in module `SmartWatch` |
| `bin/conformance.rb` | the vector runner |
| `bin/interop.rb` | the interop program for `ports/conformance/interop.py` |
| `sf-smartwatch.gemspec` | package metadata (not published) |

## Vectors and interop

From the repository root:

```sh
ruby ports/ruby/bin/conformance.rb spec/conformance   # last line: ruby: 1468/1468 vectors passed
ports/conformance/run.sh ruby                         # the same, through the shared harness
ports/conformance/interop.sh ruby                     # reporter and command poller against the Python monitor
```

## Using it

```ruby
require 'smartwatch'   # with -Iports/ruby/lib

eng = SmartWatch::Engine.new(SmartWatch.load_policy('policy.json'))
out = eng.add('planner', 'coder', 1_700_000_000_123, 4)   # Array of output Hashes, often empty
out = eng.flush(SmartWatch.wall_ms)
stats = eng.snapshot

client = SmartWatch::Client.new('http://127.0.0.1:8730', ENV['SMARTWATCH_INGEST_TOKEN'])
rep = SmartWatch::Reporter.new(client).start
rep.record('planner', 'coder')       # never blocks on the network
poller = SmartWatch::CommandPoller.new(client, 'coder', interval: 1.0) { |cmd| restart_my_agent }.start
...
rep.close                            # stops the thread and sends what is left
poller.stop
```

- Engine outputs are Hashes with String keys and the fields of SEMANTICS.md section 6.
- An invalid event or policy raises `SmartWatch::WatchError`. Its `code` holds the `WATCH-*` code.
- Only `Integer` counts as an integer, so `1.5` and `true` are refused.
- The engine is not thread-safe.
- `Reporter` sends from a background thread every 1 s, plus or minus up to 200 ms of random jitter. Each
  request holds at most 10,000 events, sorted by time, then src, then dst.
- A network error or a 5xx answer keeps the events for the next send. A 400, 401, 403 or 413 answer drops
  them, and they are counted in `rejected`. At most 100,000 keys are kept; later messages are counted in
  `dropped`. `sent` counts the messages the monitor accepted.
- `CommandPoller` acknowledges a command only when the block returns normally. A block that raises gets the
  command again on the next poll.
- Each request opens a new connection. Net::HTTP does not follow redirects. Answers longer than 32 MiB are
  refused.
- Errors are reported with `warn`.

## Implementation notes and limits

- FNV-1a 64 keeps its state in two 32-bit halves, because its prime is 2^40 + 0x1b3. This keeps the hot loop
  in small integers. mix64 uses Integer arithmetic masked to 64 bits.
- The 2^20 bucket counters are a sparse `Hash`, holding only the buckets that were touched. A missing bucket
  counts as 0, which matches the specification.
- The candidate set uses a binary heap with lazy deletion of stale entries, as the Python reference does.
