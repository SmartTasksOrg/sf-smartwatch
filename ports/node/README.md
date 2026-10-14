# SmartWatch for Node.js (engine and agent side)

This is the SmartWatch engine and agent side in JavaScript for Node.js. The engine is the
deterministic part of `spec/SEMANTICS.md`: it counts messages between agents per window, computes the
coupling density, grades it into levels and decides when a reset is due. The agent side is a reporter
that sends message counts to the Python monitor and a command poller that receives reset commands and
acknowledges them. The shared vectors in `spec/conformance` test the engine. The HTTP monitor itself
(proposals, webhooks, audit file, JWT) stays in the Python reference.

It uses only the Node.js standard library (`crypto`, `http`, `https`) and has no dependencies. It is not
published on npm or any other registry (`"private": true`). Use it from a clone of this repository.

## Layout

| Path | What |
|---|---|
| `src/canonical.js` | canonical JSON (`dumps`, `encode`), `sha256Hex` |
| `src/hashing.js` | seeded FNV-1a 32/64 and `mix64` |
| `src/hll.js` | `HyperLogLog` (p = 14) |
| `src/policy.js` | `validate`, `Policy`, `DEFAULT_POLICY` |
| `src/calibrate.js` | `thresholds`, `PROFILES` |
| `src/engine.js` | `Engine` (add / flush / snapshot), `densityMicro`, `checkEvent` |
| `src/audit.js` | `verify` and `recordHash` for the audit chain |
| `src/client.js` | `Client`, `Reporter`, `CommandPoller` |
| `src/errors.js` | `PolicyError` (`WATCH-BAD-POLICY`), `EventError` (`WATCH-BAD-EVENT`) |
| `test/conformance.js` | the vector runner |
| `test/client.js` | the reporter and poller against an in-process fake monitor |
| `bin/interop.js` | the interop program for `ports/conformance/interop.py` |

## Conformance and interop

From the repository root:

```sh
node ports/node/test/conformance.js spec/conformance   # last line: node: 1472/1472 vectors passed
node ports/node/test/client.js                         # node: client tests passed
ports/conformance/run.sh node                          # the vectors through the shared harness
ports/conformance/interop.sh node                      # reporter and poller against the Python monitor
```

The interop test needs Python 3 and the Python reference installed (see the repository README). It runs
`node ports/node/bin/interop.js URL AGENT_IDS SECONDS`.

## Using it

```js
const sw = require('./ports/node/src');

const eng = new sw.Engine(new sw.Policy(policyDoc));   // throws PolicyError
eng.add('planner', 'coder', 1700000000123, 4);         // -> outputs of the windows it closes
eng.flush(Date.now());                                 // closes the windows the clock says are complete
eng.snapshot();

const rep = new sw.Reporter('http://watch.example:8730', process.env.SMARTWATCH_INGEST_TOKEN).start();
rep.record('planner', 'coder');                        // never blocks on the network
await rep.close();                                     // stops the loop and sends what is left

const client = new sw.Client('http://watch.example:8730', process.env.SMARTWATCH_INGEST_TOKEN);
const poller = new sw.CommandPoller(client, 'coder', (cmd) => restartMyAgent(cmd.reset_id), 1000).start();
```

- `Reporter` keeps one counter per (src, dst, second), sends every 1 s ± 200 ms, at most 10,000 events
  per request, and keeps at most 100,000 keys (`dropped` counts what did not fit). A network error or
  any other failed answer keeps the events for the next send; 400, 401, 403 and 413 drop them
  (`rejected`). `sent` is the number of messages the monitor accepted.
- `CommandPoller` calls the handler for every `reset` command (the handler may return a promise) and
  acknowledges it when the handler did not throw. A command whose handler threw comes back on the next
  poll.
- Each request uses its own connection (no keep-alive). Redirects are not followed. One timeout
  (5 s by default) covers a whole request.
- The background timers are unref'd: they do not keep the process alive.

## Numbers

- The 64-bit hashes are BigInt where they are returned (`fnv1a64`, `mix64`). Inside the HyperLogLog,
  FNV-1a 64 runs on two 32-bit halves in Numbers and only `mix64` uses BigInt.
- The hysteresis comparison in `grade` (`density × 1000` against `threshold × (1000 − h)`) can exceed
  2^53 and uses BigInt.
- `n (n − 1) / 2` and `floor(ts_ms / window_ms)` are computed in a form that stays exact for every
  allowed value. The density and the HyperLogLog estimate use doubles in the order the spec gives.
- JSON is parsed with `JSON.parse`. A parsed `2.5`, `true` or `"1"` is rejected where an integer is
  required. `1.0` cannot be told apart from `1` after parsing, so a policy with `"window_ms": 1000.0` is
  accepted here and refused by the Python reference. Integers above 2^53 − 1 are rejected where the spec
  bounds them, but `JSON.parse` rounds them, so their exact value is not kept.
- `thresholds` refuses a density that is not an integer >= 0 (as the reference does).

## What was tested

Node 22.22.0 on Linux x86-64, with the Python reference on Python 3.13.16 for the interop test:
the 1472 vectors, `test/client.js`, `interop.sh node` (run repeatedly), and a differential run of about
13,800 random engine steps (sketch mode, evictions, late events, silences, resets) generated with the
Python engine. `package.json` declares Node >= 18; versions other than 22 were not tested.

## Limits

- An `Engine` holds plain in-memory state: use one instance from one thread (worker threads do not
  share it).
- A window over the exact pair limit allocates 2^20 counters (8 MiB, `Float64Array`).
- `hash_seed` with a lone UTF-16 surrogate is refused (the Python reference refuses it too).
